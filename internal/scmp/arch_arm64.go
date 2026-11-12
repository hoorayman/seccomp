//go:build linux && arm64

package scmp

const AuditArch = 0xC00000B7 // AUDIT_ARCH_AARCH64

const ArchName = "arm64"

// sysSeccomp 是 seccomp(2) 的系统调用号。
const sysSeccomp = 277
