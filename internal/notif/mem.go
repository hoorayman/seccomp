package notif

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// ReadCString 从另一个进程的地址空间读一个 C 字符串。
//
// 为什么必须这么麻烦？因为 seccomp_data.args[] 里只有指针的数值，
// 指针指向的内存只有目标进程才有权访问。supervisor 要么通过
// /proc/<tid>/mem 读（需要 ptrace 权限），要么通过 process_vm_readv。
//
// 这里读到的永远是"快照"：读的这一刻是什么就是什么，
// 下一秒目标进程的另一个线程可以把它改掉。所以——
// 读到之后必须基于这份快照自己动手（打开文件 + 注入 fd），
// 绝不能告诉内核"我看过了，你继续执行吧"。
func ReadCString(pid int, addr uint64, max int) (string, error) {
	// /proc/<pid>/mem。这是 Linux 提供的一个特殊文件，允许你直接读写指定进程的虚拟内存。这就是跨进程读内存的核心手段。
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("打开 /proc/%d/mem: %w（容器里常见原因是缺 CAP_SYS_PTRACE）", pid, err)
	}
	defer f.Close()

	buf := make([]byte, max)
	n, err := f.ReadAt(buf, int64(addr))
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("读 /proc/%d/mem@0x%x: %w", pid, addr, err)
	}
	if n == 0 {
		return "", fmt.Errorf("读到 0 字节")
	}
	i := bytes.IndexByte(buf[:n], 0)
	if i < 0 {
		return "", fmt.Errorf("字符串在 %d 字节内没有结束符（可能不是 C 字符串）", max)
	}
	return string(buf[:i]), nil
}
