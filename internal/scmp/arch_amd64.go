//go:build linux && amd64

package scmp

const AuditArch = 0xC000003E // AUDIT_ARCH_X86_64

const ArchName = "x86_64"

// sysSeccomp 是 seccomp(2) 的系统调用号。
// Go 的 syscall 包没生成这一项，只能自己写死——顺带说明 syscall 号是架构相关的。
const sysSeccomp = 317
