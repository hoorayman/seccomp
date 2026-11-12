// Package scmp 直接把 seccomp(2) / prctl(2) 裸系统调用包了一层。
//
// 术语对照：
//
//	过滤器(filter)  = 一段 cBPF 字节码
//	动作(action)    = 过滤器返回值里的高 16 位，比如 ALLOW / ERRNO / USER_NOTIF
//	seccomp_data    = 内核喂给 BPF 程序的"数据包"，含 nr/arch/ip/args[6]
package scmp

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"seccomplab/internal/bpf"
)

// seccomp(2) 的 operation
const (
	SetModeStrict  = 0
	SetModeFilter  = 1
	GetActionAvail = 2
)

// seccomp(2) 的 flags
const (
	FlagLog              = 1 << 1 // 只记录不拦截（配合 RET_LOG）
	FlagSpecAllow        = 1 << 2
	FlagNewListener      = 1 << 3 // 关键：为 SECCOMP_RET_USER_NOTIF 创建 listener fd
	FlagTSync            = 1 << 4 // 把过滤器同步到本进程所有线程
	FlagTSyncESRCH       = 1 << 5
	FlagWaitKillableRecv = 1 << 6 // 5.19+：等待通知可被致命信号打断
)

// prctl(2) 的 option
const (
	prSetNoNewPrivs = 38
)

// seccomp_data 里的偏移，写 BPF 程序时要用
const (
	OffNr   = 0  // int nr，syscall编号
	OffArch = 4  // __u32 arch
	OffIP   = 8  // __u64 instruction_pointer
	OffArgs = 16 // __u64 args[6]，每个占 8 字节
)

// ArgOff 返回第 i 个参数的偏移。
// 注意：cBPF 的 ld [off] 一次只读 32 位，x86_64 小端下正好读到低 32 位。
func ArgOff(i int) uint32 { return uint32(OffArgs + 8*i) } // 用于获取系统调用的参数

// 过滤器返回值：高 16 位是动作，低 16 位是动作的数据（比如 errno）
const (
	RetKillProcess = 0x80000000 // 杀整个进程组里的这个进程（不可捕获）
	RetKillThread  = 0x00000000 // 只杀这个线程
	RetTrap        = 0x00030000 // 发 SIGSYS，这个是发给本线程
	RetErrno       = 0x00050000 // 返回 | 低 16 位 作为 errno。语义：跳过执行，返回 -errno，内核会帮你取负数
	RetUserNotif   = 0x7fc00000 // 交给 listener fd 的用户态进程裁决（5.0+），就是supervisor
	RetTrace       = 0x7ff00000 // 交给 ptrace 的 tracer
	RetLog         = 0x7ffc0000 // 只记录，然后放行
	RetAllow       = 0x7fff0000 // 放行
)

// Errno 把 errno 编码成返回值，用于 RET_ERRNO。
func Errno(e syscall.Errno) uint32 { return RetErrno | uint32(e)&0xffff }

// seccomp_notif / seccomp_notif_resp / seccomp_notif_addfd 这三个结构体
// 必须和内核 include/uapi/linux/seccomp.h 里的布局逐字节一致。
// 这里故意不写 padding，靠 Go 的自然对齐——因为内核里也是自然对齐的。

// Data 对应 struct seccomp_data（64 字节）。
type Data struct {
	Nr   int32
	Arch uint32
	IP   uint64 // instruction_pointer是触发调用的那条指令地址——调试时配合 /proc/<tid>/maps(一个 Linux 虚拟文件，作用是展示指定线程（tid）当前内存地址空间的映射情况) 能直接定位到是哪个库、哪一行发的调用，排查"谁在偷偷 open 文件"特别有用。
	Args [6]uint64
}

// Notif 对应 struct seccomp_notif（80 字节）。
//
// 内核填好 Data 后放到 listener 的队列里，等用户态 ioctl(RECV) 取走。
type Notif struct {
	ID    uint64 // 通知ID
	PID   uint32 // 发起系统调用的*线程*的 tid
	Flags uint32 // 基本是0，留给未来扩展
	Data  Data
}

// NotifResp 对应 struct seccomp_notif_resp（24 字节）。
//
// 注意语义：SEND 并不是"让系统调用继续"，而是"用 Val/Error 伪造这次系统调用的返回值"。
// 想真的执行系统调用只能带 SECCOMP_USER_NOTIF_FLAG_CONTINUE，而那是不安全的（见 README）。
//
// Error 必须是 **负** errno：内核把 Error 原样塞进返回寄存器。填 +EPERM 不会得到
// EPERM，而是得到一个"成功返回 1"的系统调用——静默放行，比直接报错危险得多。
// ======有3种互斥的裁决形态：
// 形态	    Val	  Error	  Flags	       实际发生
// 拒绝	     0	 -EPERM	   0	    跳过执行，返回 -EPERM
// 伪造成功	 任意值	 0	     0	      跳过执行，返回 Val
// 真的执行	  0 	0	  CONTINUE	 内核重新执行这次系统调用
// ===========================
type NotifResp struct { // 这是 supervisor 发给 内核的裁决书
	ID    uint64 // 这个必须和通知ID一致，表示答的是哪条通知
	Val   int64  // 伪造的返回值（Error 为 0 时生效），意思就是：这个系统调用根本没有执行，但我告诉你它成功了，返回值就用我给的数字。
	Error int32  // 负 errno，例如 -EPERM
	Flags uint32
}

// UserNotifFlagContinue 让内核"继续执行"被拦下的系统调用。
const UserNotifFlagContinue = 1 << 0

// NotifAddfd 对应 struct seccomp_notif_addfd（24 字节）。
//
// 这是 USER_NOTIF 里唯一"安全"的放行方式：supervisor 自己打开文件/建 socket，
// 然后把 fd 塞进被监控进程的 fd 表，并把 fd 号作为系统调用返回值。
// 把 supervisor 手里的一个 fd，复制进目标进程的 fd 表，并返回"在目标进程里"的号码。
// 它是 USER_NOTIF 里唯一能"代劳"的原语——CONTINUE 是"批准"，ADDFD 是"我替你做"。
// dup() 只能复制自己进程的 fd。想在别人的 fd 表里装一个 fd，普通进程没有任何办法——files_struct 有锁、有权限，只有内核能安全地写。所以内核开了这个后门
type NotifAddfd struct { // 你 → 内核   代劳（id + srcfd + 目标 fd 属性）
	ID         uint64 // 这个必须和通知ID一致，表示答的是哪条通知
	Flags      uint32 // AddfdFlagSetfd=用 NewFD 指定号码；AddfdFlagSend=注入完自动 SEND（5.14+）
	SrcFD      uint32 // supervisor 这边的 fd
	NewFD      uint32 // 0 = 让内核挑一个；配合 AddfdFlagSetfd 可指定
	NewFDFlags uint32 // 只能是 O_CLOEXEC 的子集
}

const (
	AddfdFlagSetfd = 1 << 0 // NewFD 有效，它*不会唤醒睡眠的线程*，所以后面必须再补一个SEND
	AddfdFlagSend  = 1 << 1 // 5.14+：添加 fd 的同时原子地 SEND 响应，*以唤醒睡眠的线程*
)

// NoNewPrivs 设置 PR_SET_NO_NEW_PRIVS。
//
// 非 root 进程安装 seccomp 过滤器必须先打开这个开关；它同时也阻止了
// 沙箱里的进程通过 setuid 程序提权（配合 execve 才有意义）。
// 主要是为了污染特权进程，比如一个设置了seccomp的普通进程，setuid到root后，root进程也会受到seccomp的限制
func NoNewPrivs() error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", errno)
	}
	return nil
}

// Install 安装过滤器。
//
// 返回 listener fd（只在 flags 含 FlagNewListener 时有意义，其它情况返回 -1）。
//
// 两个容易踩的点：
//  1. seccomp 过滤器天然是"每线程"的，Go 程序一启动就有多个线程，
//     所以必须带 *FlagTSync*，否则只有当前线程被约束，其它线程照跑不误。
//  2. FlagNewListener 返回的 fd 带 O_CLOEXEC，想让它活过 execve 必须自己清掉。
func Install(p *bpf.Prog, flags uintptr, noNewPrivs bool) (int, error) {
	if noNewPrivs { // 普通用户必须设，否则 seccomp 会返回 EACCES。
		if err := NoNewPrivs(); err != nil {
			return -1, err
		}
	}
	fprog := p.Fprog()
	r1, _, errno := syscall.Syscall(sysSeccomp,
		SetModeFilter, flags, uintptr(unsafe.Pointer(fprog)))
	// **GC 判断一个对象能不能回收，看的是从当前执行点往后，还有没有代码会用到这个变量，而不是看它是不是还在函数的作用域里。
	// 所以KeepAlive 保证 p 活到系统调用返回之后。
	runtime.KeepAlive(p)
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SECCOMP_SET_MODE_FILTER, flags=0x%x): %w", flags, errno)
	}
	// TSYNC 失败时内核通过返回值给出"捣乱的那个线程的 tid"，
	// 此时 errno 不会被设置，r1 是个正数，容易被误当成成功。
	// FlagNewListener 是 seccomp 过滤器的一种特殊安装模式，它的核心作用是：安装过滤器后，不再只是简单地放行或拒绝系统调用，而是返回一个文件描述符（fd），让用户态程序能够“监听”并接管特定的系统调用。
	// FlagNewListener 和 TSYNC 是互斥的，不能同时使用。
	// 原因在于返回值的语义冲突：
	//   TSYNC 失败时：返回值是一个正数（肇事线程的 tid）。
	//   FlagNewListener 成功时：返回值也是一个正数（新的监听 fd）。
	//   内核无法仅凭返回值区分“TSYNC 失败了”还是“NewListener 成功了”。
	if flags&FlagNewListener == 0 && r1 != 0 {
		return -1, fmt.Errorf("seccomp TSYNC 失败，肇事线程 tid=%d", r1)
	}
	return int(r1), nil
}

// ActionsAvail 读 /proc/sys/kernel/seccomp/actions_avail，
// 可以看当前内核支持哪些 RET_* 动作（user_notif 需要 5.0+）。
func ActionsAvail() string {
	b, err := os.ReadFile("/proc/sys/kernel/seccomp/actions_avail")
	if err != nil {
		return "读取失败: " + err.Error()
	}
	return string(b)
}
