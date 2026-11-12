// Demo 03 角色三：payload（被监控的业务进程）
//
// 这个程序里没有任何 seccomp 代码——它只是普通地 open/write/read，
// 完全不知道每次写打开都被内核挂起、被另一个进程审了一遍。
// 这是 USER_NOTIF 最有价值的地方：对业务完全透明。
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

const (
	allowFile = "/tmp/lab/allow/hello.txt"
	denyFile  = "/tmp/lab/deny/pwned.txt"
)

func main() {
	fmt.Println("== Demo 03 角色三: payload（被监控的业务进程）==")
	fmt.Printf("pid=%d\n", os.Getpid())

	// 把继承来的 listener fd 关掉。
	// 监控不会因此失效：supervisor 持有同一个 struct file 的另一份引用，
	// 过滤器里的 notification 对象就还活着。反过来，supervisor 一旦退出
	// （所有引用都没了），这些被拦的系统调用会全部变成 ENOSYS。
	if s := os.Getenv("LISTENER_FD"); s != "" {
		if fd, err := strconv.Atoi(s); err == nil {
			syscall.Close(fd)
			fmt.Printf("已关闭继承来的 listener fd=%d（监控照旧，因为 supervisor 还握着它）\n", fd)
		}
	}

	fmt.Println("\n-- 1. 写白名单目录里的文件（会被拦截，但由 supervisor 代劳）--")
	if err := writeFile(allowFile, "written through the supervisor\n"); err != nil {
		fmt.Println("失败:", err)
	} else {
		fmt.Println("成功:", allowFile)
	}

	fmt.Println("\n-- 2. 写目录外的文件（会被拦截并拒绝）--")
	if err := writeFile(denyFile, "should never land here\n"); err != nil {
		fmt.Printf("失败（预期就是失败）: %v\n", err)
	} else {
		fmt.Println("居然成功了？！策略有 bug")
	}

	fmt.Println("\n-- 3. 只读打开不受影响（过滤器只拦写打开，且根本没上报）--")
	b, err := os.ReadFile("/etc/hostname")
	if err != nil {
		fmt.Println("读 /etc/hostname 失败:", err)
	} else {
		fmt.Printf("读到 %d 字节，说明只读路径完全没被拦\n", len(b))
	}

	fmt.Println("\n-- 4. socket 也不在过滤器里，网络功能正常 --")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	fmt.Printf("socket(AF_UNIX) = %d, err=%v\n", fd, err)
	if err == nil {
		syscall.Close(fd)
	}
}

func writeFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}
