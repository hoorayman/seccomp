package notif

import (
	"fmt"
	"syscall"
)

// SendFD 通过 unix socket 把 fd 递给另一个进程（SCM_RIGHTS）。
//
// 这是"双角色"架构的关键一步：装过滤器的进程把自己拿到的 listener fd
// 交给沙箱外的 supervisor，之后两者之间只靠这个内核队列通信。
func SendFD(sock, fd int) error {
	// 构造一个控制消息（cmsg），类型是 SCM_RIGHTS，里面装的就是要传的 fd。这是 Unix 域套接字传递 fd 的标准方式。
	// SCM_RIGHTS 是 Unix 域套接字（Unix domain socket）里的一种控制消息类型，专门用来在进程之间传递文件描述符（file descriptor）。
	oob := syscall.UnixRights(fd)
	// 把数据和控制消息一起发出去。这里数据部分只发了一个字节 'F'，其实内容无所谓，真正有意义的是 oob 里的 fd。Sendmsg 会保证 fd 随消息一起被内核传递。
	if err := syscall.Sendmsg(sock, []byte{'F'}, oob, nil, 0); err != nil {
		return fmt.Errorf("sendmsg(SCM_RIGHTS): %w", err)
	}
	return nil
}

// RecvFD 接收对端传来的 fd。
func RecvFD(sock int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4))
	// 最后一个 0 是 flags：不带任何可选行为（不 MSG_PEEK / MSG_DONTWAIT / MSG_CMSG_CLOEXEC）。
	// 它跟"阻塞"没关系——阻塞与否看 socket 自身的 O_NONBLOCK：阻塞 socket + flags=0 会等，
	// 非阻塞 socket 即使 flags=0 也立刻返回 EAGAIN（实测）。这里能阻塞等，是因为 sock 是阻塞的。
	_, oobn, _, _, err := syscall.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return -1, fmt.Errorf("recvmsg: %w", err)
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("解析控制消息: %w", err)
	}
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("对端没有传 fd 过来")
}
