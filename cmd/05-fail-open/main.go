// Demo 05：supervisor 没了会怎样？—— fail-open 的边界。
//
// USER_NOTIF 的"安全"完全建立在"listener 还有人守着"这个前提上。
// 一旦 listener 的最后一个引用被关掉（supervisor 崩了、被 kill、fd 泄漏），
// 所有被拦的系统调用不再被挂起，而是立刻返回 ENOSYS。
//
// 注意 ENOSYS 不是 EPERM：
//   - 调用者看到的是"这个系统调用不存在"，而不是"你被禁止了"。
//   - 很多程序（glibc、Go runtime、各种工具）对 ENOSYS 有降级路径，
//     会换一条老系统调用继续干同样的事。
//   - 也就是说，监控者死亡时，沙箱不会变紧，而是悄悄变松。
//
// 所以生产环境必须把 "supervisor 活着" 当成硬性约束：
// 用 pidfd 盯着、用 PR_SET_PDEATHSIG、或者干脆把安全策略下沉到内核过滤器里
// （USER_NOTIF 只作为可选的增强层）。
package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"seccomplab/internal/notif"
	"seccomplab/internal/scmp"
)

func main() {
	fmt.Println("== Demo 05: listener 被关掉之后的 fail-open ==")

	p := scmp.NotifyList([]uint32{uint32(syscall.SYS_SOCKET)})
	listenerFd, err := scmp.Install(p, scmp.FlagNewListener|scmp.FlagTSync, true)
	if err != nil {
		fmt.Println("安装过滤器失败:", err)
		os.Exit(1)
	}
	fmt.Printf("listener fd = %d\n", listenerFd)

	n := notif.Open(listenerFd)
	go func() {
		req, err := n.Receive()
		if err == nil {
			fmt.Printf("[supervisor] 收到 tid=%d 的 socket 通知，放行\n", req.PID)
			n.RespondContinue(req.ID)
		}
	}()

	// 场景 A：supervisor 还活着，正常裁决。
	fmt.Println("\n-- A. listener 有效 --")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	fmt.Printf("socket() = %d, err = %v\n", fd, err)
	if err == nil {
		syscall.Close(fd)
	}

	// 场景 B：把 listener 关掉（等价于 supervisor 进程挂掉）。
	fmt.Println("\n-- B. 关掉 listener（等价于 supervisor 挂了）--")
	if err := n.Close(); err != nil {
		fmt.Println("关闭失败:", err)
	}
	fmt.Println("listener 已关闭")

	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	fmt.Printf("socket() = %d, err = %v\n", fd, err)
	if errors.Is(err, syscall.ENOSYS) {
		fmt.Println("-> ENOSYS：内核直接告诉进程\"没有这个系统调用\"，没有挂起、没有报错、没有审计日志。")
		fmt.Println("   监控者死亡 = 策略静默失效。这就是为什么 supervisor 的存活本身是安全边界。")
	}
	if err == nil {
		syscall.Close(fd)
	}
}
