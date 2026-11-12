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
	os.Remove(sockPath)

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

	// 1) dirfd 必须真的是 CWD，否则路径可以相对某个目录被"拼"出来，
	//    校验的路径和实际打开的路径就不是一回事了（dirfd 逃逸）。
	if dirfd != -100 { // AT_FDCWD
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
