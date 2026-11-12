package scmp

import (
	"strconv"
	"syscall"

	"seccomplab/internal/bpf"
)

// writeOpenMask 用来判断"这次 openat 是不是要写"。
// 只读打开不拦，程序启动时 Go runtime 读 /sys、/proc 的那堆 openat 才会自然放行，
// 不会一上来就把自己憋死。
// writeOpenMask表示”所有open标志位代表这次要动文件”的位掩码。后续只需要flags & writeOpenMask != 0 就说明这是写操作。
const writeOpenMask = uint32(syscall.O_WRONLY | syscall.O_RDWR |
	syscall.O_CREAT | syscall.O_TRUNC | syscall.O_APPEND)

// archGuard 是所有过滤器共用的第一步：校验架构。
//
// 为什么必须做？因为 syscall 号是跟 ABI 绑定的。同一颗 x86_64 内核上，
// 一个 32 位进程发出来的 nr=41 是 socket，而 64 位进程的 nr=41 是 socketpair。
// 不校验 arch 就等于让攻击者换一个 ABI 把你的黑名单绕过。
//
// 另外 x32 ABI 的坑：x32 进程的 nr 会带上 0x40000000 位，arch 仍然是 X86_64，
// 严谨的过滤器还要额外判断 nr >= 0x40000000 就杀。
func archGuard(p *bpf.Prog) *bpf.Prog {
	p.LD(OffArch)
	p.JEQ(AuditArch, 1, 0) // arch 对 -> 跳过下一条
	p.RET(RetKillProcess)
	return p
}

// BlockList 生成一个"命中即拒绝"的过滤器：命中 nrs 里的系统调用就返回 action
// （通常用 Errno(syscall.EPERM)），其余一律放行。
//
// 生成的字节码长这样：
//
//	ld [4]                ; arch
//	jeq ARCH, 1, 0
//	ret KILL
//	ld [0]                ; nr
//	jeq nr0, 0, 1         ; 不等就跳过 ret
//	ret ACTION
//	jeq nr1, 0, 1
//	ret ACTION
//	...
//	ret ALLOW

// 系统调用号命中列表就返回 action,否则放行。
func BlockList(nrs []uint32, action uint32) *bpf.Prog {
	p := archGuard(bpf.New())
	p.LD(OffNr)
	for _, nr := range nrs {
		p.JEQ(nr, 0, 1)
		p.RET(action)
	}
	p.RET(RetAllow)
	return p
}

// NotifyList 生成一个"命中即上报用户态"的过滤器，其它放行。
// 内核会把这些系统调用挂起，塞进 listener fd 的队列里等 supervisor 裁决。
func NotifyList(nrs []uint32) *bpf.Prog {
	return BlockList(nrs, RetUserNotif)
}

// NotifyWriteOpenAt 只拦"以写方式打开的 openat"。
//
//	openat(dirfd, path, flags, mode)
//	                    ^^^^^ args[2]
//
// 用 AND 把无关位滤掉，再判断是否为 0：为 0 说明是纯只读打开，直接放行。
// 生成一个"只拦写方式打开的 openat"的过滤器——只读打开完全放行，写打开上报 supervisor，其余系统调用一律放行。
func NotifyWriteOpenAt() *bpf.Prog {
	p := archGuard(bpf.New())
	p.LD(OffNr)
	p.JEQ(uint32(syscall.SYS_OPENAT), 0, 4) // 不是 openat -> 跳到最后的 ret ALLOW
	p.LD(ArgOff(2))                         // flags，小端低 32 位
	p.AND(writeOpenMask)
	p.JEQ(0, 1, 0) // 不含写标志 -> 跳过 ret USER_NOTIF
	p.RET(RetUserNotif)
	p.RET(RetAllow)
	return p
}

var syscallNames = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	41:  "socket",
	42:  "connect",
	49:  "bind",
	59:  "execve",
	87:  "unlink",
	101: "ptrace",
	165: "mount",
	257: "openat",
	262: "newfstatat",
	263: "unlinkat",
	316: "renameat2",
	317: "seccomp",
	322: "execveat",
	437: "openat2",
}

// Name 把 syscall 号翻译成人话，日志里好看。
func Name(nr uint32) string {
	if s, ok := syscallNames[nr]; ok {
		return s
	}
	return "syscall#" + strconv.FormatUint(uint64(nr), 10)
}
