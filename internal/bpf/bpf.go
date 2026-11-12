// Package bpf 是一个"够用就好"的经典 BPF(cBPF) 汇编器。
//
// seccomp 过滤器在内核里就是一段 cBPF 字节码：内核把当前系统调用的信息
// 塞进一个结构体 seccomp_data，然后拿它当 "数据包" 跑一遍这段 BPF 程序，
// 程序的返回值决定这次系统调用的命运（放行 / 返回错误 / 杀进程 / 交给用户态）。
//
// 这里故意不依赖 libseccomp，手写指令编码，方便看清楚每一层到底发生了什么。
package bpf

import (
	"fmt"
	"strings"
)

// Insn 对应内核 struct sock_filter —— 一条 cBPF 指令，恰好 8 字节。
type Insn struct { // instruction的缩写
	Code uint16 // 操作码（class|size|mode|opcode 组合出来的 16 位）
	Jt   uint8  // 条件为真时向前跳过的指令条数
	Jf   uint8  // 条件为假时向前跳过的指令条数
	K    uint32 // 立即数 / 偏移量
}

// Fprog 对应内核 struct sock_fprog。
//
//	len 是 uint16，后面跟着 8 字节对齐的指针，
//	所以 64 位下这个结构体是 16 字节（len 后面有 6 字节 padding），
//	Go 的布局和内核布局一致。
type Fprog struct { // filter program的缩写。这是历史原因。cBPF 最早是套接字过滤器（socket filter），seccomp 后来复用了这套 cBPF 虚拟机，直接沿用这两个结构体，没有另起名字。
	// Go 的 gc 编译器排字段只有一条规则：
	// 每个字段的偏移，必须是该字段类型对齐值的整数倍。
	// 所以，指针必须落在 8 的倍数上，而 Len 只占了 2 字节，中间的空隙没人能填，只能留白。
	Len    uint16
	Filter *Insn
}

// cBPF 操作码（只列本仓库用到的）
// 它们是无类型常量（untyped constant）——Go 里常量默认不带类型，用在哪就变成哪的类型。
const (
	// A：累加器，唯一的工作寄存器，所有计算围绕它
	// W是word，32位
	// ABS是absolute，是指数据包seccomp_data的绝对的偏移
	opLD_W_ABS  = 0x20 // A = *(u32 *)(data + k)
	opALU_AND_K = 0x54 // A &= k
	// program counter直接往前跳 k 条指令。注意 cBPF 只能向前跳，不能往回跳（保证程序必然终止）
	opJMP_JA     = 0x05 // pc += k
	opJMP_JEQ_K  = 0x15 // if A == k { pc += jt } else { pc += jf }
	opJMP_JGT_K  = 0x25 // if A >  k
	opJMP_JGE_K  = 0x35 // if A >= k
	opJMP_JSET_K = 0x45 // if A &  k，非零则跳转Jt，零则跳转Jf
	opRET_K      = 0x06 // return k，在 seccomp 里，k 必须是一个 SECCOMP_RET_* 动作码：SECCOMP_RET_ALLOW、SECCOMP_RET_ERRNO、SECCOMP_RET_KILL_PROCESS、SECCOMP_RET_TRAP
	// “Trap”（陷阱）指的是从正常执行流中强制跳转到一个处理程序的动作，而发送信号正是实现这种跳转的手段。seccomp这里发送给当前进程的是SIGSYS信号，表示system call发送的信号
)

// Prog 是一个可增量构造的 BPF 程序。
type Prog struct { // program的缩写
	ins []Insn
}

func New() *Prog { return &Prog{} }

func (p *Prog) add(code uint16, jt, jf uint8, k uint32) *Prog {
	p.ins = append(p.ins, Insn{Code: code, Jt: jt, Jf: jf, K: k})
	return p
}

// LD 把 seccomp_data 中偏移 off 处的 32 位（小端低半部分）装进累加器 A。
func (p *Prog) LD(off uint32) *Prog { return p.add(opLD_W_ABS, 0, 0, off) }

// AND 对 A 做按位与。
func (p *Prog) AND(k uint32) *Prog { return p.add(opALU_AND_K, 0, 0, k) }

// JEQ 相等则向前跳 jt 条，否则向前跳 jf 条。
func (p *Prog) JEQ(k uint32, jt, jf uint8) *Prog { return p.add(opJMP_JEQ_K, jt, jf, k) }

func (p *Prog) JGE(k uint32, jt, jf uint8) *Prog { return p.add(opJMP_JGE_K, jt, jf, k) }

func (p *Prog) JGT(k uint32, jt, jf uint8) *Prog { return p.add(opJMP_JGT_K, jt, jf, k) }

func (p *Prog) JSET(k uint32, jt, jf uint8) *Prog { return p.add(opJMP_JSET_K, jt, jf, k) }

// JMP 无条件向前跳。
func (p *Prog) JMP(off uint8) *Prog { return p.add(opJMP_JA, 0, 0, uint32(off)) }

// RET 返回一个 SECCOMP_RET_* 动作。
func (p *Prog) RET(k uint32) *Prog { return p.add(opRET_K, 0, 0, k) }

// Len 指令条数。
func (p *Prog) Len() int { return len(p.ins) }

// Fprog 生成可以直接交给 seccomp(2) 的结构体。
func (p *Prog) Fprog() *Fprog {
	return &Fprog{Len: uint16(len(p.ins)), Filter: &p.ins[0]}
}

// String 反汇编，方便打印出来对着看。
func (p *Prog) String() string {
	var b strings.Builder
	for i, in := range p.ins {
		name, operand := opName(in.Code)
		fmt.Fprintf(&b, " [%02d] %-10s %-12s", i, name, operand(in.K))
		if in.Code == opJMP_JEQ_K || in.Code == opJMP_JGE_K || in.Code == opJMP_JGT_K || in.Code == opJMP_JSET_K {
			// i+1+int(in.Jt), i+1+int(in.Jf)是为了把相对跳转换算成绝对下标，纯粹为了人读。
			fmt.Fprintf(&b, " jt=%d jf=%d  ->  t:%d f:%d", in.Jt, in.Jf, i+1+int(in.Jt), i+1+int(in.Jf))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// opName 返回助记符和对应的操作数格式化函数。
// 每种指令怎么显示，只在这里定义一处——反汇编的可读性规则不该散在调用方。
func opName(code uint16) (string, func(uint32) string) {
	hex := func(k uint32) string { return fmt.Sprintf("0x%08x", k) }
	dec := func(k uint32) string { return fmt.Sprintf("%d", k) }
	// ld 的 K 是 seccomp_data 里的字节偏移，用十进制加方括号最像反汇编
	brk := func(k uint32) string { return fmt.Sprintf("[%d]", k) }
	switch code {
	case opLD_W_ABS:
		return "ld", brk
	case opALU_AND_K:
		return "and", hex
	case opJMP_JA:
		return "jmp", dec
	case opJMP_JEQ_K:
		return "jeq", hex
	case opJMP_JGT_K:
		return "jgt", hex
	case opJMP_JGE_K:
		return "jge", hex
	case opJMP_JSET_K:
		return "jset", hex
	case opRET_K:
		return "ret", hex
	default:
		return "?", hex
	}
}
