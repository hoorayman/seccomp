// Package notif 封装 SECCOMP_RET_USER_NOTIF 的用户态一侧：
// listener fd 上的 4 个 ioctl、SCM_RIGHTS 传 fd、读目标进程内存。
//
// 内核提供的四个命令：
//
//	SECCOMP_IOCTL_NOTIF_RECV      阻塞取一条通知
//	SECCOMP_IOCTL_NOTIF_SEND      伪造这次系统调用的返回值（放行或拒绝）
//	SECCOMP_IOCTL_NOTIF_ID_VALID  确认通知对应的线程还活着（防 pid 复用）
//	SECCOMP_IOCTL_NOTIF_ADDFD     把 supervisor 的 fd 塞进目标进程并返回 fd 号
package notif

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"seccomplab/internal/scmp"
)

// ioctl 号是算出来的，不是背下来的：_IOC(dir, type, nr, size)
//
//	dir: 1=写内核 2=读内核 3=读写
//	size: 结构体大小，所以结构体一旦对不上，这里的号也不对，立刻就会 ENOTTY。
const (
	iocWrite     = 1
	iocRead      = 2
	iocReadWrite = 3
	iocType      = '!'
)

func ioc(dir, nr, size uintptr) uintptr {
	return dir<<30 | size<<16 | iocType<<8 | nr
}

var (
	ioctlRecv    = ioc(iocReadWrite, 0, unsafe.Sizeof(scmp.Notif{}))
	ioctlSend    = ioc(iocReadWrite, 1, unsafe.Sizeof(scmp.NotifResp{}))
	ioctlIDValid = ioc(iocWrite, 2, unsafe.Sizeof(uint64(0)))
	ioctlAddfd   = ioc(iocWrite, 3, unsafe.Sizeof(scmp.NotifAddfd{}))
)

// Notifier 是 listener fd 的用户态句柄。
//
// 注意：它本身不带任何锁。真正的实现里，一个 listener 可以有多个消费者
// （多个线程/多个 supervisor 进程 recv 同一个 fd），这正是"惊群"和
// "通知被别的进程截胡"的来源，也是为什么一个 listener 只给一个可信 supervisor。
type Notifier struct {
	fd int
}

func Open(fd int) *Notifier { return &Notifier{fd: fd} }

func (n *Notifier) Fd() int { return n.fd }

func (n *Notifier) Close() error { return syscall.Close(n.fd) }

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// Receive 阻塞等待下一条通知。没有通知时线程睡在 listener 的等待队列上。
//
// 可能的错误：
//   - EINTR：被信号打断，重试即可
//   - ENOENT：这条通知对应的线程已经死了（比如被 SIGKILL），重试即可
//   - ENOSYS：listener 已经被关闭（所有引用都没了）
func (n *Notifier) Receive() (*scmp.Notif, error) {
	req := new(scmp.Notif)
	if err := ioctl(n.fd, ioctlRecv, unsafe.Pointer(req)); err != nil {
		return nil, err
	}
	return req, nil
}

// Send 提交裁决结果。
//
// 语义非常反直觉，务必看清：
//   - Error != 0  -> 系统调用不执行，直接返回 -Error
//   - Error == 0  -> 系统调用不执行，直接返回 Val
//   - Flags = CONTINUE -> 才真的让内核去执行这次系统调用（危险，见 README）
func (n *Notifier) Send(resp *scmp.NotifResp) error {
	if err := ioctl(n.fd, ioctlSend, unsafe.Pointer(resp)); err != nil {
		return fmt.Errorf("ioctl(NOTIF_SEND): %w", err)
	}
	return nil
}

// RespondErr 让系统调用返回 errno。
//
// 坑：Error 字段必须是 **负的** errno。内核直接把它写进返回寄存器
// （x86 上是 regs->ax = error ?: val），填正数 1 不会变成 EPERM，
// 而是让系统调用"成功返回 1"——静默变成放行，非常危险。
func (n *Notifier) RespondErr(id uint64, errno syscall.Errno) error {
	return n.Send(&scmp.NotifResp{ID: id, Error: -int32(errno)})
}

// RespondVal 伪造一个返回值。
func (n *Notifier) RespondVal(id uint64, val int64) error {
	return n.Send(&scmp.NotifResp{ID: id, Val: val})
}

// RespondContinue 让内核真的去执行这次系统调用。
//
// 只有在"判定只依赖标量参数"时才是安全的（比如 socket 的 domain/type/protocol）。
// 一旦判定依赖指针指向的内存（路径名、缓冲区），就是 TOCTOU 灾难。
func (n *Notifier) RespondContinue(id uint64) error {
	return n.Send(&scmp.NotifResp{ID: id, Flags: scmp.UserNotifFlagContinue})
}

// RespondENOSYS 让系统调用表现为"内核不支持"，常用于把决定权交还给调用者
// （比如给容器里跑的新内核程序留一个降级路径）。
func (n *Notifier) RespondENOSYS(id uint64) error {
	return n.Send(&scmp.NotifResp{ID: id, Error: -int32(syscall.ENOSYS)})
}

// IDValid 在真正动手（打开文件、注入 fd）之前再确认一次：
// 这条通知背后的线程还在、tid 没被复用。
//
// 典型攻击：agent 收到 openat 通知 -> 目标进程恰好退出 -> pid 被一个
// 高权限进程复用 -> agent 按旧通知干了一件"替别人"的事。
// 内核用 (id) 而不是 (pid) 来标识通知，ID_VALID 就是唯一正确的存活性检查。
func (n *Notifier) IDValid(id uint64) error {
	if err := ioctl(n.fd, ioctlIDValid, unsafe.Pointer(&id)); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("通知 %d 已失效（线程已退出）: %w", id, err)
		}
		return fmt.Errorf("ioctl(NOTIF_ID_VALID): %w", err)
	}
	return nil
}

// Addfd 把 supervisor 的 srcfd 复制进被监控进程的 fd 表。
//
// 返回值是"在目标进程里"的 fd 号，正是 open/socket 这类系统调用该返回的东西。
// 这一步是 USER_NOTIF 里唯一没有 TOCTOU 的放行方式：
// 特权操作（打开文件）由 supervisor 用自己的权限、按自己的判断完成，
// 目标进程只能拿到结果，改不了过程。
func (n *Notifier) Addfd(req *scmp.NotifAddfd) (int, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(n.fd), ioctlAddfd, uintptr(unsafe.Pointer(req)))
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// AddfdAndSend 一步完成"注入 fd + 把 fd 号当返回值"。
//
// 5.14+ 支持 AddfdFlagSend，注入与响应是原子的；老内核退化成
// ADDFD 之后再 Send，中间有一个极小的窗口（目标进程可能死掉），
// 所以老内核路径上要先用 IDValid 检查一次。
func (n *Notifier) AddfdAndSend(id uint64, srcfd int, newfdFlags uint32) (int, error) {
	req := &scmp.NotifAddfd{
		ID:         id,
		Flags:      scmp.AddfdFlagSend,
		SrcFD:      uint32(srcfd),
		NewFDFlags: newfdFlags,
	}
	fd, err := n.Addfd(req)
	if err == nil {
		return fd, nil
	}
	if !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTTY) {
		return -1, err
	}

	// 老内核：分两步走。
	if err := n.IDValid(id); err != nil {
		return -1, err
	}
	req.Flags = 0
	fd, err = n.Addfd(req)
	if err != nil {
		return -1, err
	}
	if err := n.RespondVal(id, int64(fd)); err != nil {
		return -1, err
	}
	return fd, nil
}
