// Demo 02：SECCOMP_RET_USER_NOTIF 最小例子（单进程自监督）。
//
// 结构：一个进程里两拨人
//
//	主 goroutine  -> 发起 socket(2)
//	另一个 goroutine -> 从 listener fd 收通知、做裁决
//
// 这个写法只适合理解机制，绝对不是一个安全的沙箱架构，原因见文件末尾和 README：
// supervisor 和"被监控者"在同一个进程、同一个地址空间、同一套权限里，
// 中间没有任何边界可言。
//
// 关键语义（很多人第一次都会理解错）：
//   - SEND 不是"让系统调用继续"，而是"伪造它的返回值"。
//   - 想真的执行，只能带 SECCOMP_USER_NOTIF_FLAG_CONTINUE。
//   - 目标线程在收到裁决前是被内核挂起的，但它同进程的其它线程不受影响。
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"seccomplab/internal/notif"
	"seccomplab/internal/scmp"
)

func main() {
	// 装过滤器和发 socket() 必须在同一个 OS 线程上，否则可能漂到未过滤的线程
	// 导致"演示偶尔不灵"（详见 README 坑 10）。
	runtime.LockOSThread()

	fmt.Println("== Demo 02: USER_NOTIF —— 把系统调用交给用户态裁决 ==")

	p := scmp.NotifyList([]uint32{uint32(syscall.SYS_SOCKET)})
	fmt.Print(p.String())

	// NEW_LISTENER 和 TSYNC 不能裸用（EINVAL），5.7+ 必须补上 TSYNC_ESRCH，见 README 坑 10。
	listener, err := scmp.Install(p, scmp.FlagNewListener|scmp.FlagTSync|scmp.FlagTSyncESRCH, true)
	if err != nil {
		fmt.Println("安装过滤器失败:", err)
		os.Exit(1)
	}
	fmt.Printf("\nlistener fd = %d（这个 fd 是内核给你的通知管道）\n\n", listener)

	n := notif.Open(listener)
	go supervise(n)

	fmt.Println("-- 目标进程发起 socket(2) --")
	for _, tc := range []struct {
		name   string
		domain int
		typ    int
	}{
		{"AF_UNIX (本机通讯，放行)", syscall.AF_UNIX, syscall.SOCK_STREAM},
		{"AF_INET (外网，拒绝)", syscall.AF_INET, syscall.SOCK_STREAM},
		{"AF_INET6 (外网，拒绝)", syscall.AF_INET6, syscall.SOCK_STREAM},
	} {
		fd, err := syscall.Socket(tc.domain, tc.typ, 0)
		fmt.Printf("socket(%-8s) -> fd=%-3d err=%v\n", tc.name, fd, err)
		if err == nil {
			syscall.Close(fd)
		}
	}
}

// supervise 是"临时 supervisor"。
//
// 它的每一次 Receive 都对应某个线程被卡在 socket(2) 里。
func supervise(n *notif.Notifier) {
	for {
		req, err := n.Receive()
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ENOENT) {
				continue
			}
			fmt.Println("[supervisor] 收通知出错:", err)
			return
		}

		a := req.Data.Args
		domain, typ, proto := a[0], a[1], a[2]
		fmt.Printf("[supervisor] tid=%-5d 拦截 %s(domain=%d, type=%d, proto=%d)\n",
			req.PID, scmp.Name(uint32(req.Data.Nr)), domain, typ, proto)

		switch domain {
		case syscall.AF_INET, syscall.AF_INET6:
			// 拒绝：不执行，直接返回 -EPERM。
			fmt.Println("[supervisor]   -> 拒绝 (返回 EPERM)")
			if err := n.RespondErr(req.ID, syscall.EPERM); err != nil {
				fmt.Println("[supervisor]   响应失败:", err)
			}
		default:
			// 放行：让内核真的去执行。
			//
			// 这里用 CONTINUE 是安全的，因为判断只依赖 domain/type/proto 这三个
			// 标量值——它们来自寄存器，不存在"读到一半被别人改掉"的问题。
			// 一旦判断依赖指针指向的内存（比如 openat 的路径），CONTINUE 就完蛋了。
			fmt.Println("[supervisor]   -> 放行 (CONTINUE，判定只用了标量参数)")
			if err := n.RespondContinue(req.ID); err != nil {
				fmt.Println("[supervisor]   响应失败:", err)
			}
		}
	}
}
