// Demo 01：最朴素的 seccomp 过滤器。
//
// 目标：不涉及用户态，全靠内核里的 BPF 程序做决定。
// 观察点：
//  1. 过滤器就是一串 cBPF 指令，可以打印出来看。
//  2. 命中黑名单的系统调用直接返回 EPERM，进程继续活着。
//  3. 没被拦的系统调用完全不受影响（所以进程不会莫名其妙挂掉）。
//  4. 过滤器是"每线程"的，Go 程序必须用 TSYNC 才能盖住所有线程。
//  5. 装了就不能卸，只能往上叠加，且层层取最严格的动作。
package main

import (
	"fmt"
	"os"
	"syscall"

	"seccomplab/internal/scmp"
)

func main() {
	fmt.Println("== Demo 01: 用 BPF 过滤器直接拒绝系统调用 ==")
	fmt.Println("内核支持的动作:", scmp.ActionsAvail())

	blocked := []uint32{
		uint32(syscall.SYS_SOCKET),  // socket(2)  —— 最常见的网络出口
		uint32(syscall.SYS_MKDIRAT), // mkdirat(2) —— os.Mkdir 走这个
		uint32(syscall.SYS_PTRACE),  // ptrace(2)  —— 调试/注入
	}

	p := scmp.BlockList(blocked, scmp.Errno(syscall.EPERM))
	fmt.Println("\n过滤器字节码（这就是真正进内核的东西）:")
	fmt.Print(p.String())

	// PR_SET_NO_NEW_PRIVS + TSYNC：非 root 也能装，并且盖住所有线程。
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

	// ptrace 一般还要 CAP_SYS_PTRACE，这里因为过滤器先生效，直接是 EPERM。
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
