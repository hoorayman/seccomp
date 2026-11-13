// Demo 04：USER_NOTIF 的"异步坑"实证 —— CONTINUE 的 TOCTOU。
//
// 场景：
//
//  1. 过滤器只把"写方式打开的 openat"上报给用户态。
//  2. supervisor 从目标进程内存里读出路径，看到 /tmp/lab/allow/ok.txt，判定安全。
//  3. supervisor 为了演示，故意睡 800ms 再响应。
//  4. 另一个线程在这 800ms 里，把同一块内存改成了 /tmp/lab/deny/pwned.txt。
//  5. supervisor 回 CONTINUE，内核"重新执行"openat —— 重新读了那块内存。
//
// 结果：supervisor 日志说"批准了 allow/ok.txt"，实际被打开的是 deny/pwned.txt。
//
// 结论：只要裁决依赖指针指向的内存，就绝不能 CONTINUE。
// 正确做法是 demo 03 的 ADDFD —— 由 supervisor 按自己读到的快照亲自执行操作。
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"seccomplab/internal/notif"
	"seccomplab/internal/scmp"
)

const (
	allowDir  = "/tmp/lab/allow"
	denyDir   = "/tmp/lab/deny"
	allowPath = "/tmp/lab/allow/ok.txt"
	denyPath  = "/tmp/lab/deny/pwned.txt"
)

func main() {
	// 装过滤器 + 发起 openat 必须钉在同一个线程上（README 坑 10）：
	// 否则 openat 可能跑在未过滤的线程上，压根不会有通知，demo 就"不灵"了。
	runtime.LockOSThread()

	fmt.Println("== Demo 04: CONTINUE 的 TOCTOU 竞态 ==")

	for _, d := range []string{allowDir, denyDir} {
		must(os.MkdirAll(d, 0o777))
		os.Chmod(d, 0o777)
	}
	os.Remove(allowPath)
	os.Remove(denyPath)

	p := scmp.NotifyWriteOpenAt()
	listenerFd, err := scmp.Install(p, scmp.FlagNewListener|scmp.FlagTSync|scmp.FlagTSyncESRCH, true)
	must(err)
	fmt.Printf("过滤器已安装，listener fd = %d\n\n", listenerFd)

	n := notif.Open(listenerFd)
	go naiveSupervisor(n)

	// 把两条路径放进同一块内存，先写好"合法"的那条。
	buf := make([]byte, len(denyPath)+1)
	copy(buf, allowPath)
	ptr := uintptr(unsafe.Pointer(&buf[0]))

	// 攻击者线程：等 supervisor 读完路径、还没响应时，把内存改掉。
	go func() {
		time.Sleep(300 * time.Millisecond)
		copy(buf, denyPath)
		fmt.Printf("[attacker] 已把路径改成 %q（supervisor 还以为自己批的是 %q）\n", denyPath, allowPath)
	}()

	fmt.Printf("[payload] 发起 openat(%q, O_WRONLY|O_CREAT)\n", allowPath)
	atFDCWD := -100
	fd, _, errno := syscall.Syscall6(syscall.SYS_OPENAT, uintptr(atFDCWD), ptr,
		uintptr(syscall.O_WRONLY|syscall.O_CREAT), 0o644, 0, 0)
	if errno != 0 {
		fmt.Println("[payload] openat 失败:", errno)
		os.Exit(1)
	}
	target, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	fmt.Printf("[payload] openat 成功，fd=%d 实际指向 %q\n", fd, target)
	syscall.Close(int(fd))

	// 留点时间给 attacker 打印
	time.Sleep(100 * time.Millisecond)

	fmt.Println("\n---- 现场 ----")
	report(allowPath)
	report(denyPath)

	fmt.Println(`
结论：
  supervisor 的日志说它批准的是 ` + allowPath + `，
  但真正被打开、被创建的是 ` + denyPath + `。
  裁决和执行之间隔了一个"重新执行"，中间目标进程可以随意改内存。
  这就是为什么 CONTINUE 只适用于"判定只用标量参数"的场合（例如 socket 的 domain），
  也是为什么真正安全的做法必须是 demo 03 的 ADDFD：自己执行，不让内核重跑。`)
}

// naiveSupervisor 是一个"看起来对、实际上错"的 supervisor。
func naiveSupervisor(n *notif.Notifier) {
	for {
		req, err := n.Receive()
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ENOENT) {
				continue
			}
			fmt.Println("[supervisor] 出错:", err)
			return
		}

		// 读一份快照（真实实现里就是 /proc/<pid>/mem）
		path, err := notif.ReadCString(int(req.PID), req.Data.Args[1], 256)
		if err != nil {
			fmt.Println("[supervisor] 读路径失败:", err)
			n.RespondErr(req.ID, syscall.EPERM)
			continue
		}
		fmt.Printf("[supervisor] 读到路径 %q，判定：安全\n", path)

		// 模拟"裁决需要点时间"：查数据库、做审计、甚至只是调度延迟。
		time.Sleep(800 * time.Millisecond)

		fmt.Println("[supervisor] 回 CONTINUE：批准执行")
		if err := n.RespondContinue(req.ID); err != nil {
			fmt.Println("[supervisor] 响应失败:", err)
		}
	}
}

func report(path string) {
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("  %-28s 存在\n", path)
	} else {
		fmt.Printf("  %-28s 不存在\n", path)
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("fatal:", err)
		os.Exit(1)
	}
}
