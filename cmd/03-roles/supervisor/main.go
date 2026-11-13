// Demo 03 角色一：supervisor（仲裁者）
//
// 它自己的进程里 **没有** 装过滤器，所以它读文件、开 socket、写日志、fork
// 全都不受限制——这正是双角色架构的意义：裁决者必须站在沙箱外面。
//
// 职责：
//  1. 从 unix socket 收下 listener fd（SCM_RIGHTS）
//  2. 循环 RECV 通知
//  3. 对 openat：从目标进程内存读出路径 -> 按策略校验 -> 自己打开文件
//     -> ADDFD 把 fd 注入目标进程 -> 顺便作为 openat 的返回值
//  4. 全程不信任目标进程传来的任何东西
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"seccomplab/internal/notif"
	"seccomplab/internal/scmp"
)

const (
	sockPath   = "/tmp/lab/sup.sock"
	allowDir   = "/tmp/lab/allow/"
	denyDir    = "/tmp/lab/deny/"
	maxPathLen = 512
)

func main() {
	fmt.Println("== Demo 03 角色一: supervisor（沙箱外，不受过滤器约束）==")

	setupDirs()
	// AF_UNIX 的路径是文件系统里一个真实的 socket inode，进程退出不会自动消失（不像 TCP 端口），
	// 所以上一次跑的残留会让这次的 bind() 直接 EADDRINUSE。先删掉。
	// 注意这是"盲删"：如果真有一个活着的 supervisor，删掉路径只会让它变成没人能连的孤儿，
	// 新的那个谁先绑上谁说了算——所以目录权限必须收紧。更稳的做法是先 connect 探活，
	// 或者改用抽象命名空间（名字以 '\0' 开头，不进文件系统、进程一退就没了）。
	os.Remove(sockPath)

	lfd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	check(err, "socket")
	syscall.CloseOnExec(lfd)
	check(syscall.Bind(lfd, &syscall.SockaddrUnix{Name: sockPath}), "bind")
	check(syscall.Listen(lfd, 1), "listen")
	fmt.Println("等待 launcher 连接:", sockPath)

	cfd, _, err := syscall.Accept(lfd)
	check(err, "accept")

	listenerFd, err := notif.RecvFD(cfd)
	check(err, "接收 listener fd")
	syscall.Close(cfd)
	syscall.Close(lfd)
	os.Remove(sockPath) // 收工顺手清掉自己创建的那个 inode，免得下次运行撞 EADDRINUSE

	fmt.Printf("收到 listener fd = %d，开始仲裁\n\n", listenerFd)
	n := notif.Open(listenerFd)
	serve(n)
}

func serve(n *notif.Notifier) {
	for {
		req, err := n.Receive()
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ENOENT) {
				// ENOENT = 发起调用的线程已经死了，丢弃这条通知即可
				continue
			}
			fmt.Println("RECV 失败:", err)
			return
		}
		handle(n, req)
	}
}

func handle(n *notif.Notifier, req *scmp.Notif) {
	a := req.Data.Args
	dirfd := int32(a[0])
	pathPtr := a[1]
	// openat 的 flags/mode 在内核里是 unsigned int，
	// 所以只能取低 32 位——寄存器的上半部分是什么，谁都说不准。
	flags := int(uint32(a[2]))
	mode := uint32(a[3]) & 0o777

	fmt.Printf("[recv] tid=%-5d %s(dirfd=%d, path=0x%x, flags=0x%x, mode=0%o)\n",
		req.PID, scmp.Name(uint32(req.Data.Nr)), dirfd, pathPtr, flags, mode)

	deny := func(reason string) {
		fmt.Printf("[deny] tid=%-5d %s -> EPERM\n", req.PID, reason)
		if err := n.RespondErr(req.ID, syscall.EPERM); err != nil {
			fmt.Println("[deny] 响应失败:", err)
		}
	}

	// 1) openat 的 dirfd 决定"相对路径以谁为基准解析"：
	//    真实的目录 fd → 相对那个目录；AT_FDCWD（内核约定的魔法值 -100）→ 相对**调用进程自己的 cwd**。这里访问的绝对路径（像cmd/03-roles/payload/main.go），AT_FDCWD不起作用，不影响。
	//    这里只接受后者。否则目标进程可以传一个自己打开的目录 fd，把"校验的字符串"和
	//    "实际会被打开的文件"错开——supervisor 后面是用这个字符串在**自己的** cwd 下重新
	//    open 的，两边基准一旦不同就是 dirfd 逃逸。
	if dirfd != -100 { // AT_FDCWD == -100
		deny(fmt.Sprintf("dirfd=%d 不是 AT_FDCWD，本 demo 不支持相对路径", dirfd))
		return
	}

	// 2) 从目标进程内存里把路径读出来（这是一份快照）
	path, err := notif.ReadCString(int(req.PID), pathPtr, maxPathLen)
	if err != nil {
		deny("读路径失败: " + err.Error())
		return
	}

	clean, err := validate(path)
	if err != nil {
		deny(fmt.Sprintf("路径 %q 被策略拒绝: %v", path, err))
		return
	}
	fmt.Printf("[allow] tid=%-5d 路径 %q 通过策略检查\n", req.PID, clean)

	// 3) 由 supervisor 自己打开。注意 O_NOFOLLOW：
	//    allow 目录里如果被人塞了一个指向 /etc/shadow 的符号链接，
	//    跟着链接打开就等于自己把沙箱门打开了。
	srcFlags := flags | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	sfd, err := syscall.Open(clean, srcFlags, mode)
	if err != nil {
		fmt.Printf("[allow] 自己打开 %q 失败: %v\n", clean, err)
		if err := n.RespondErr(req.ID, errnoOf(err)); err != nil {
			fmt.Println("[allow] 响应失败:", err)
		}
		return
	}
	defer syscall.Close(sfd)

	// 4) 动手之前再确认一次通知还有效（防 tid 复用）
	if err := n.IDValid(req.ID); err != nil {
		fmt.Println("[allow] 通知已失效，放弃:", err)
		return
	}

	// 5) 把 fd 塞进目标进程，并把 fd 号作为 openat 的返回值。
	//    目标进程拿到的就是 supervisor 亲自打开的那个文件，
	//    这中间没有任何"先检查后使用"的时间差。
	//
	//    注意这条日志要在 ioctl 之前打：ADDFD 一返回，目标进程就被解封了，
	//    日志顺序会看起来像"目标先成功、supervisor 后决定"。
	fmt.Printf("[allow] tid=%-5d 用 supervisor 的权限打开成功，注入 fd 并把 fd 号回填给目标\n", req.PID)
	// supervisor 先自己把文件打开，再把那个 fd「塞进」目标进程的 fd 表，并把这个 fd 号当作目标进程 openat 的返回值。
	if _, err := n.AddfdAndSend(req.ID, sfd, syscall.O_CLOEXEC); err != nil {
		fmt.Println("[allow] ADDFD 失败:", err)
	}
}

// validate 是策略：只允许 allowDir 下的绝对路径。
//
// 真实产品还会做：路径长度限制、拒绝 "..", 检查每一级父目录的 owner/权限、
// 用 openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) 一次性完成解析和打开。
func validate(path string) (string, error) {
	if path == "" {
		return "", errors.New("空路径")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("只接受绝对路径")
	}
	// filepath.Clean(path) 的作用是对路径进行“清理”，返回一个在词法上最简化的路径。它不检查路径是否存在，只做纯字符串层面的规范化。
	// 🧹 它具体做什么
	// 消除多余的斜杠：a//b → a/b
	// 处理 .（当前目录）：a/./b → a/b，单独的 . 会变成 .
	// 处理 ..（上级目录）：a/b/../c → a/c，能消掉的 .. 会被消掉
	// 去掉末尾的斜杠：a/b/ → a/b（根目录 / 除外）
	// 空字符串变成 .：Clean("") 返回 .
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, allowDir) {
		return "", fmt.Errorf("不在白名单目录 %s 下", allowDir)
	}
	if strings.Contains(clean, "\x00") {
		return "", errors.New("路径里含 NUL")
	}
	return clean, nil
}

func errnoOf(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return syscall.EIO
}

func setupDirs() {
	for _, d := range []string{allowDir, denyDir} {
		check(os.MkdirAll(d, 0o777), "mkdir "+d)
		os.Chmod(d, 0o777)
	}
}

func check(err error, what string) {
	if err != nil {
		fmt.Printf("%s 失败: %v\n", what, err)
		os.Exit(1)
	}
}
