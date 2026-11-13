// Demo 01：最朴素的 seccomp 过滤器。
//
// 目标：不涉及用户态，全靠内核里的 BPF 程序做决定。
// 观察点：
//  1. 过滤器就是一串 cBPF 指令，可以打印出来看。
//  2. 命中黑名单的系统调用直接返回 EPERM，进程继续活着。
//  3. 没被拦的系统调用完全不受影响（所以进程不会莫名其妙挂掉）。
//  4. 过滤器是"每线程"的；TSYNC 能盖住本进程所有线程，但失败时"静默返回 tid"，
//     所以仍然要 LockOSThread 兜底（见 README 坑 10）。
//  5. 装了就不能卸，只能往上叠加，且层层取最严格的动作。
package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"seccomplab/internal/scmp"
)

func main() {
	// 关键：把本 goroutine 钉死在这一个 OS 线程上。
	//
	// seccomp 过滤器是"每线程"的，而 goroutine 会在多个 M（OS 线程）之间漂移。
	// 一旦后面那句 socket() 漂到了没装过滤器的线程上，演示就会"偶尔不灵"——
	// 而且它不报错，只会静静地放行。Go 程序一启动就有 5~7 个线程，
	// 所以"没有其他 goroutine"并不等于"只有一个线程"。
	runtime.LockOSThread()
	// runtime.LockOSThread() 的作用是将调用它的 Goroutine 与当前的操作系统线程（OS Thread）绑定，确保这个 Goroutine 始终在这个特定的线程上执行，
	// **并且在此期间，不会有其他 Goroutine 被调度到这个线程上运行。

	fmt.Println("== Demo 01: 用 BPF 过滤器直接拒绝系统调用 ==")
	fmt.Println("内核支持的动作:", scmp.ActionsAvail())

	blocked := []uint32{
		uint32(syscall.SYS_SOCKET),  // socket(2)  —— 最常见的网络出口
		uint32(syscall.SYS_MKDIRAT), // mkdirat(2) —— os.Mkdir 走这个
		uint32(syscall.SYS_PTRACE),  // ptrace(2)  —— 调试/注入
	}

	p := scmp.BlockList(blocked, scmp.Errno(syscall.EPERM)) // 返回的就是 RetErrno，只是把低 16 位的数据位填上了。
	fmt.Println("\n过滤器字节码（这就是真正进内核的东西）:")
	fmt.Print(p.String())

	// PR_SET_NO_NEW_PRIVS + TSYNC：非 root 也能装，TSYNC 让 Go runtime 已经起来的
	// 线程全部盖上过滤器（实测有效）。但同步失败时内核不设 errno，只返回肇事 tid，
	// 所以真正"不会漏"的保证仍然来自上面那句 LockOSThread。
	if _, err := scmp.Install(p, scmp.FlagTSync, true); err != nil {
		fmt.Println("安装过滤器失败:", err)
		os.Exit(1)
	}
	fmt.Println("过滤器已安装（无法卸载）")

	fmt.Println("\n-- 被拦的系统调用 --")

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	fmt.Printf("socket(AF_INET, SOCK_STREAM) = %d, err = %v\n", fd, err)

	err = os.Mkdir("/tmp/lab-should-fail", 0o755)
	fmt.Printf("os.Mkdir(/tmp/lab-should-fail) err = %v\n", err)

	// ptrace 一般还要 CAP_SYS_PTRACE，这里**因为过滤器先生效**，直接是 EPERM。
	err = syscall.PtraceAttach(os.Getpid())
	fmt.Printf("ptrace(PTRACE_ATTACH, self) err = %v\n", err)

	fmt.Println("\n-- 没被拦的系统调用照常工作 --")
	tmp, err := os.CreateTemp("", "seccomp-*")
	if err != nil {
		fmt.Println("os.CreateTemp 失败:", err)
		os.Exit(1)
	}
	fmt.Fprintf(tmp, "hello seccomp\n")
	tmp.Close()
	b, _ := os.ReadFile(tmp.Name())
	fmt.Printf("写文件再读回: %q\n", string(b))
	os.Remove(tmp.Name())

	fmt.Println("\n进程还活着，说明 ERRNO 只是让单个系统调用失败，不影响进程。")
	fmt.Println("如果动作换成 RET_KILL_PROCESS，这一行就永远打印不出来了。")
}
