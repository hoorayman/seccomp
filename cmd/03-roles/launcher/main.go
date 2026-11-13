// Demo 03 角色二：launcher（装过滤器的人，最后会变成 payload 本身）
//
// 顺序很重要：
//
//	连接 supervisor -> 装过滤器（拿到 listener fd）-> 把 fd 递出去
//	-> execve(payload)   ← listener fd 保持 CLOEXEC，execve 时自动关掉
//
// 为什么要在 execve 之前装？因为过滤器挂在 task 上，execve 之后依然生效，
// 而 pid 不变——supervisor 收到的通知里的 pid，就是它当初 fork 出来的那个进程。
// 这是把"装过滤器的代码"和"业务代码"解耦的标准做法：
// 业务进程不需要有任何 seccomp 相关代码，甚至不需要知道自己在被审。
package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"seccomplab/internal/notif"
	"seccomplab/internal/scmp"
)

const sockPath = "/tmp/lab/sup.sock"

func main() {
	// 这条尤其重要：过滤器装在"当前线程"上，而 execve 只保留"执行它的那个线程"
	// 的过滤器。如果装完过滤器和 execve 之间 goroutine 漂到别的 M 上，
	// 出来的 payload 会是一个完全没被监控的进程（而且毫无报错）。
	runtime.LockOSThread()

	payload := "./bin/03-payload"
	if len(os.Args) > 1 {
		payload = os.Args[1]
	}

	fmt.Println("== Demo 03 角色二: launcher（装过滤器 + 交接 fd + execve）==")
	// 🔌 Unix 域套接字的本质
	// Unix 域套接字（AF_UNIX）是同一台机器上进程间通信的机制。它不像 TCP 那样走网络协议栈，而是直接在内核里传递数据，效率高。
	//
	// 它有两种使用方式：
	// 匿名套接字对：用 socketpair() 直接创建一对已连接的 fd，双方不需要名字。
	// 命名套接字：一个进程用 bind() 把自己的套接字绑定到一个文件系统路径上，其他进程通过这个路径 connect() 过来。你这段代码用的是第二种。
	//
	// 📁 那个“文件”到底是什么
	// 当 supervisor 调用 bind() 时，内核会在指定路径（比如 sockPath）创建一个特殊文件，ls -l 看到类型是 s（socket）。这个文件不是数据存储，而是一个“联系地址”或“门牌号”。它的唯一作用是让客户端知道“该往哪里连”。
	// 真正的套接字对象（缓冲区、连接状态）都在内核内存里，和这个文件无关。文件只是给客户端一个可寻址的入口。
	sock, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	check(err, "socket")
	syscall.CloseOnExec(sock) // 别把这个 socket 漏给 payload
	check(syscall.Connect(sock, &syscall.SockaddrUnix{Name: sockPath}), "连接 supervisor")

	p := scmp.NotifyWriteOpenAt()
	fmt.Print(p.String())

	// 非 root 安装 seccomp 必须 no_new_privs；TSYNC 让 Go runtime 的所有线程都盖上，
	// 但要和 NEW_LISTENER 一起用得补 TSYNC_ESRCH，否则 EINVAL（README 坑 10）。
	listenerFd, err := scmp.Install(p, scmp.FlagNewListener|scmp.FlagTSync|scmp.FlagTSyncESRCH, true)
	check(err, "安装过滤器")
	fmt.Printf("listener fd = %d，交给 supervisor\n", listenerFd)

	check(notif.SendFD(sock, listenerFd), "传递 listener fd")
	syscall.Close(sock)

	// 这里**故意什么都不做**：listener fd 是内核用 CLOEXEC 建的，execve 时会自动关掉，
	// 于是 payload 拿不到它——这正是我们要的。
	//
	// 裁决权 = 这个 fd 能不能读：谁握着它，谁就能决定沙箱里的 syscall 是放行还是拒绝。
	// 把它漏给 payload，等于把钥匙交给被审的人：
	//   - payload 可以自己读通知、自己回 CONTINUE，策略形同虚设；
	//   - 更糟的是 payload 崩了或被换掉之前，这份引用让通知队列一直活着，
	//     被拦的 syscall 不会 fail-open 成 ENOSYS（demo5 那套），而是永远挂住。
	//
	// 所以正确姿势是：只经 SCM_RIGHTS 交给 supervisor，自己这份让 execve 收走。
	// （如果确实需要 fd 活过 execve，得用 fcntl(fd, F_SETFD, 0) 清掉 FD_CLOEXEC——
	//  execve 看的是这个位，不是 file 的 f_flags。但本 demo 不需要。）

	fmt.Println("execve payload，自己变成被监控进程")
	// 下面syscall.Exec直接在同一个进程中执行payload，execve 会把整个地址空间换掉：旧镜像里的 environ 随旧镜像一起消失，新程序拿到的 envp 完全来自 execve 的第三个参数。所谓“自动继承”其实不存在。所以要加os.Environ()。
	check(syscall.Exec(payload, []string{payload, "--payload"}, os.Environ()), "execve")
}

func check(err error, what string) {
	if err != nil {
		fmt.Printf("%s 失败: %v\n", what, err)
		os.Exit(1)
	}
}
