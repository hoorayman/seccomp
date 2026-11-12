// Demo 03 角色二：launcher（装过滤器的人，最后会变成 payload 本身）
//
// 顺序很重要：
//
//	连接 supervisor -> 装过滤器（拿到 listener fd）-> 把 fd 递出去
//	-> 清掉 fd 的 O_CLOEXEC -> execve(payload)
//
// 为什么要在 execve 之前装？因为过滤器挂在 task 上，execve 之后依然生效，
// 而 pid 不变——supervisor 收到的通知里的 pid，就是它当初 fork 出来的那个进程。
// 这是把"装过滤器的代码"和"业务代码"解耦的标准做法：
// 业务进程不需要有任何 seccomp 相关代码，甚至不需要知道自己在被审。
package main

import (
	"fmt"
	"os"
	"syscall"

	"seccomplab/internal/notif"
	"seccomplab/internal/scmp"
)

const sockPath = "/tmp/lab/sup.sock"

func main() {
	payload := "./bin/03-payload"
	if len(os.Args) > 1 {
		payload = os.Args[1]
	}

	fmt.Println("== Demo 03 角色二: launcher（装过滤器 + 交接 fd + execve）==")

	sock, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	check(err, "socket")
	syscall.CloseOnExec(sock) // 别把这个 socket 漏给 payload
	check(syscall.Connect(sock, &syscall.SockaddrUnix{Name: sockPath}), "连接 supervisor")

	p := scmp.NotifyWriteOpenAt()
	fmt.Print(p.String())

	// 非 root 安装 seccomp 必须 no_new_privs；TSYNC 让 Go runtime 的所有线程都盖上。
	listenerFd, err := scmp.Install(p, scmp.FlagNewListener|scmp.FlagTSync, true)
	check(err, "安装过滤器")
	fmt.Printf("listener fd = %d，交给 supervisor\n", listenerFd)

	check(notif.SendFD(sock, listenerFd), "传递 listener fd")
	syscall.Close(sock)

	// 内核创建 listener fd 时带的是 O_CLOEXEC，不干掉它，execve 之后 fd 就没了，
	// 而 supervisor 手上那份 dup 还活着——所以其实也可以不传，但那意味着
	// 目标进程在 exec 的瞬间会有一小段"没有 listener"的窗口。这里保留。
	check(clearCloexec(listenerFd), "清除 O_CLOEXEC")

	fmt.Println("execve payload，自己变成被监控进程")
	env := append(os.Environ(), fmt.Sprintf("LISTENER_FD=%d", listenerFd))
	check(syscall.Exec(payload, []string{payload, "--payload"}, env), "execve")
}

func clearCloexec(fd int) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0); errno != 0 {
		return errno
	}
	return nil
}

func check(err error, what string) {
	if err != nil {
		fmt.Printf("%s 失败: %v\n", what, err)
		os.Exit(1)
	}
}
