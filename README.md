# seccomp 学习实验室

一个用 Go 手写 seccomp 过滤器的教学项目：不依赖 libseccomp，不依赖 cgo，
从 cBPF 字节码一直到 `SECCOMP_RET_USER_NOTIF` 的双角色仲裁，全程摊开给你看。

```
make image     # 构建工具链镜像（golang:1.27-bookworm）
make demo1     # 内核直接拒绝系统调用
make demo2     # USER_NOTIF 最小例子
make demo3     # supervisor / launcher / payload 三进程安全架构（含 fd 注入）
make demo4     # CONTINUE 的 TOCTOU 竞态实证
make demo5     # supervisor 死掉之后的 fail-open
```

> 环境：macOS + Docker Desktop（内核 ≥ 5.9 即可，本机验证用的是 linuxkit 7.0.14）。
> 所有代码都是 linux-only 的裸系统调用，编译器在 macOS 上只能交叉编译，必须进容器跑。
>
> **看代码看晕了？先看 [docs/flow.md](docs/flow.md)** —— 四张流程图，对应内核、通知协议、三进程架构、CONTINUE vs ADDFD 四个层次。

---

## 目录

0. [流程图总览](docs/flow.md)
1. [它是什么](#1-它是什么)
2. [能做什么 / 不能做什么](#2-能做什么--不能做什么)
3. [原理：一次系统调用是怎么被审的](#3-原理一次系统调用是怎么被审的)
4. [三种模式与 USER_NOTIF](#4-三种模式与-user_notif)
5. [异步坑清单（重点）](#5-异步坑清单重点)
6. [为什么必须双角色](#6-为什么必须双角色)
7. [项目结构与代码走读](#7-项目结构与代码走读)
8. [生产环境怎么用](#8-生产环境怎么用)
9. [参考资料](#9-参考资料)

---

## 1. 它是什么

seccomp = **sec**ure **comp**uting mode。一句话：

> **Linux 内核里唯一一个"按系统调用粒度"做强制访问控制的机制。**
> 进程发起系统调用的瞬间（还没进入具体实现），内核会拿一段 BPF 程序审它，
> 不合格就杀进程 / 返回错误 / 或者把这次调用挂起，交给另一个用户态进程裁决。

放在整体安全体系里看，它管的是**最贴近攻击面的那一层**：

| 机制 | 管什么 | 典型问题 |
|---|---|---|
| capabilities | 你能用哪些特权 | `CAP_SYS_ADMIN` 太粗 |
| namespaces | 你能看到什么 | 只隔离视图，不限制动作 |
| cgroup | 你能用多少资源 | 与"能不能做"无关 |
| LSM（SELinux/AppArmor） | 你能访问哪些对象 | 需要策略语言 + 对象标签 |
| **seccomp** | **你能发起哪些系统调用** | 只知道 syscall 号和参数原始值 |

容器逃逸、内核提权、RCE 之后的横向移动，最后几乎都要落到某个具体系统调用上：
`mount`、`unshare`、`setns`、`ptrace`、`bpf`、`keyctl`、`perf_event_open`、`io_uring_setup`……
seccomp 就是那道"你要用这些调用？先问过我"的闸门。

历史（几行就够）：

- **2005** Andrea Arcangeli 为 cpushare 写了最初的 seccomp，只有 `STRICT` 模式（只能读/写/exit/sigreturn）。
- **2012** Will Drewry 加入 `FILTER` 模式：用 cBPF 写规则，Linux 3.5。
- **2019** Linux 5.0 加入 `SECCOMP_RET_USER_NOTIF`（Tycho Andersen），seccomp 从"静态规则"变成"可编程仲裁"。
- **5.9 / 5.14 / 5.19** 陆续补上 `ADDFD`、`ADDFD_FLAG_SEND`、`WAIT_KILLABLE_RECV`，USER_NOTIF 才真正可用。

---

## 2. 能做什么 / 不能做什么

**能做：**

- 按系统调用号拦截：禁止 `mount`/`ptrace`/`bpf`/`socket`……
- 按**标量参数**拦截：只允许 `socket(AF_UNIX)`，只允许 `personality` 的某个值。
- 按**架构**拦截：拒绝 32 位 ABI（否则同一颗 x86_64 内核上，`nr=41` 在 32 位进程里是 `socket`，在 64 位进程里是 `socketpair`，黑名单直接失效）。
- 四种结局自由组合：杀进程 / 返回 errno / 发 SIGSYS / 上报用户态。
- 对业务完全透明：进程不需要任何代码改动（`launcher` 装完过滤器直接 `execve`）。

**不能做：**

- **看不到指针指向的内容。** `seccomp_data.args[]` 里只有寄存器的值：`openat` 的 pathname 只是一个地址。内核过滤器无法判断"你要打开哪个文件"。
- 不能做路径级、域名级、内容级的判断——除非把决定权交给用户态（USER_NOTIF + 自己读内存，见第 5 节的风险）。
- 不能限制资源用量（那是 cgroup）、不能限制文件访问（那是 LSM/权限）。
- 不能删除、不能放宽。装上去就是一辈子的，只能继续叠加（见 3.5）。
- 看不见 vDSO 里的调用，也看不见 `io_uring` 已经提交的异步操作（历史上已知的绕过面，所以常见黑名单直接禁 `io_uring_setup`）。

所以 seccomp 的正确定位是：**最后一道窄门，不是完整沙箱**。真正的隔离要靠 namespaces + cgroup + LSM + 用户态沙箱（gVisor/Kata/Firecracker）一起上。

---

## 3. 原理：一次系统调用是怎么被审的

### 3.1 挂载点

系统调用的入口在 `arch/x86/entry/common.c` 一路走到 `__secure_computing()` → `__seccomp_filter()`。
**在任何具体系统调用实现之前**，内核把这次调用的信息填进 `seccomp_data`，然后交给过滤器链。

关键是这个"之前"：此刻内核还没解析路径、没有 inode、没有 fd 表操作。
所以 seccomp 天生只能看到**原始参数**，看不到语义。

### 3.2 seccomp_data

```c
struct seccomp_data {
    int  nr;                    // 系统调用号        offset  0
    __u32 arch;                 // AUDIT_ARCH_*      offset  4
    __u64 instruction_pointer;  // 触发指令的地址    offset  8
    __u64 args[6];              // 六个参数          offset 16
};
```

在 `internal/scmp/scmp.go` 里就是这几个常量：

```go
const (
    OffNr   = 0
    OffArch = 4
    OffIP   = 8
    OffArgs = 16 // args[0] 在 16，args[1] 在 24，每个占 8 字节
)
```

> x86_64 是小端，`ld [off]` 一次读 32 位，读到的正好是 64 位参数的低半部分。
> 所以 `args[0]` 的低 32 位偏移是 16，高 32 位偏移是 20。

### 3.3 过滤器 = 一段 cBPF

经典 BPF（不是 eBPF），指令只有 8 字节：

```c
struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; };
```

`internal/bpf/bpf.go` 就是一个只做这件事的汇编器。用 `scmp.NotifyList` 生成一个
"拦 socket" 的过滤器，打印出来是这样（demo2 的真实输出）：

```
 [00] ld         [4]                              ; A = arch
 [01] jeq        0xc000003e   jt=1 jf=0  ->  t:3 f:2
 [02] ret        0x80000000                       ; arch 不对 -> KILL_PROCESS
 [03] ld         [0]                              ; A = nr
 [04] jeq        0x00000029   jt=0 jf=1  ->  t:5 f:6
 [05] ret        0x7fc00000                       ; nr == socket -> USER_NOTIF
 [06] ret        0x7fff0000                       ; 其余 -> ALLOW
```

就这么多。内核用 JIT 把这段字节码编成机器码，每个系统调用跑一遍，
开销是纳秒量级——这也是 seccomp 能用在每个容器里的原因。

### 3.4 返回值决定命运

返回值高 16 位是动作，低 16 位是数据：

| 动作 | 值 | 后果 | 能捕获吗 |
|---|---|---|---|
| `KILL_PROCESS` | 0x80000000 | 杀整个进程 | 不能 |
| `KILL_THREAD` | 0x00000000 | 只杀当前线程 | 不能 |
| `TRAP` | 0x00030000 | 给线程发 `SIGSYS` | 能（handler 里可读 `si_syscall`） |
| `ERRNO` | 0x00050000 | 系统调用直接返回 `-低16位` | 能（普通 errno） |
| `USER_NOTIF` | 0x7fc00000 | 挂起，等 listener fd 的用户态裁决 | 能 |
| `TRACE` | 0x7ff00000 | 交给 ptrace 的 tracer | 能 |
| `LOG` | 0x7ffc0000 | 记审计日志后放行 | —— |
| `ALLOW` | 0x7fff0000 | 放行 | —— |

### 3.5 过滤器链：只增不减，最严者胜

一个线程可以装很多层过滤器（`fork` 继承、`execve` 继承、容器 runtime 一层、应用自己再来一层）。
内核把**所有**过滤器都跑一遍，然后取**优先级最高**的那个动作：

```
KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > USER_NOTIF > TRACE > LOG > ALLOW
```

推论：

- 你没法通过"再装一个全 ALLOW 的过滤器"来放宽已有的限制。
- 反过来，`docker run --security-opt seccomp=unconfined` 只是让 **Docker 那层** 不下发，
  容器里进程自己给自己装的过滤器照样生效。
- 排查问题时，`/proc/<pid>/status` 里的 `Seccomp:`（0/1/2）和 `Seccomp_filters:`（叠加层数）
  是最快的入口。

### 3.6 生效范围（几个容易把人坑哭的点）

- **每线程生效。** 不是每进程。`clone` 出来的新线程会继承创建者的过滤器，但**如果你在 A 线程装过滤器，
  B 线程早就跑起来了，B 不受影响**。Go 程序一启动就有 6~7 个 OS 线程（实测），
  所以要么装的时候带 `TSYNC` 把已存在的线程一起盖上，要么就得保证"装过滤器的线程 =
  之后发 syscall 的线程"——本项目两者都做，细节和实测数据见
  [坑 10](#坑-10tsync-与-new_listener-必须补-tsync_esrch)。
- **`execve` 只保留"执行它的那个线程"的过滤器**，pid 不变。这是 `launcher` 模式的基础，
  也是它必须 `runtime.LockOSThread()` 的原因。
- **`execve` 后依然有效**，pid 不变。这是 `launcher` 模式的基础。
- **`fork`/`clone` 子进程继承**。所以限制住一个进程，它 spawn 出来的子孙都在笼子里。
- **非 root 必须先 `PR_SET_NO_NEW_PRIVS`。** 它顺便也堵住了 setuid 提权。
- **不能卸载**，`exit` 才消失。

---

## 4. 三种模式与 USER_NOTIF

| 模式 | 入口 | 说明 |
|---|---|---|
| `STRICT` | `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)` | 只能 read/write/_exit/sigreturn，等于废掉进程 |
| `FILTER` | `seccomp(SECCOMP_SET_MODE_FILTER, flags, prog)` | 本文的主体，cBPF 规则 |
| `USER_NOTIF` | `FILTER` + `SECCOMP_FILTER_FLAG_NEW_LISTENER` | 不自己裁决，挂起交给用户态 |

`USER_NOTIF` 的调用返回一个**新的 fd**（listener）。它是一条内核队列：

```
   被监控进程（沙箱内）                      supervisor（沙箱外）
    ┌──────────────┐                        ┌──────────────────┐
    │ socket()     │                        │                  │
    │   ↓ 命中过滤 │                        │                  │
    │ 挂起，等裁决 │  ─── 通知队列 ───▶     │ RECV 拿到通知    │
    │              │                        │ 读参数 / 读内存  │
    │              │  ◀── SEND 裁决 ─────   │ 决定放行 or 拒绝 │
    │ 拿到返回值   │                        │                  │
    └──────────────┘                        └──────────────────┘
```

四个 ioctl（`internal/notif/notif.go` 全部封装好了）：

| ioctl | 作用 |
|---|---|
| `SECCOMP_IOCTL_NOTIF_RECV` | 阻塞取一条通知（`struct seccomp_notif`） |
| `SECCOMP_IOCTL_NOTIF_SEND` | 提交裁决（`struct seccomp_notif_resp`） |
| `SECCOMP_IOCTL_NOTIF_ID_VALID` | 校验通知是否还有效（防 tid 复用） |
| `SECCOMP_IOCTL_NOTIF_ADDFD` | 把 supervisor 的 fd 注入目标进程，并作为系统调用返回值 |

这些 ioctl 号不是背下来的，是算出来的（`_IOC(dir, type, nr, size)`），
`size` 直接取 `unsafe.Sizeof(结构体)`——**结构体布局一旦和内核不一致，ioctl 号就错，立刻就 `ENOTTY`**，
这比"悄悄跑错"安全得多。

### 4.1 内核版本依赖

基础能力从 **Linux 5.0**（2019-03）开始，但后面几个补丁才让它真正可用：

| 内核版本 | 新增 | 影响 |
|---|---|---|
| **5.0** | `SECCOMP_RET_USER_NOTIF`、`NEW_LISTENER`、`RECV`/`SEND`/`ID_VALID` | 能用，但没有 `CONTINUE`，也没有 `ADDFD` |
| **5.5** | `SECCOMP_USER_NOTIF_FLAG_CONTINUE` | 才能"让内核真的执行"（demo2 / demo4 的用法） |
| **5.9** | `SECCOMP_IOCTL_NOTIF_ADDFD` | **demo3 的安全路径从这里才存在** |
| **5.14** | `SECCOMP_ADDFD_FLAG_SEND` | 注入 + 响应原子化，否则退化成 `ID_VALID` → `ADDFD` → `SEND` 三步 |
| **5.19** | `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` | 等待通知时能被致命信号打断，避免线程"杀不掉" |

编译期还需要 `CONFIG_SECCOMP=y` + `CONFIG_SECCOMP_FILTER=y`（主流发行版默认开）。

**运行时确认（最可靠，别只看 `uname -r`）：**

```bash
cat /proc/sys/kernel/seccomp/actions_avail      # 必须含 user_notif
grep Seccomp /proc/<pid>/status                 # Seccomp: 2 表示在过滤器下, Seccomp_filters: 层数
```

注意 `actions_avail` 只反映**基础动作**，`ADDFD` / `ADDFD_FLAG_SEND` 这类后来新增的 ioctl
不在里面——判断办法只能是"试一次，看是不是 `EINVAL`/`ENOTTY`"，
这正是 `notif.AddfdAndSend` 里那段回退逻辑在做的事。

**各 demo 的最低要求：**

| 想跑 | 最低内核 | 原因 |
|---|---|---|
| `demo1` | 3.5 | 只需要 cBPF 过滤器 |
| `demo2` / `demo4` | **5.5** | 需要 `CONTINUE` |
| `demo3` | **5.9** | 需要 `ADDFD` 才能"代劳" |
| `demo3` 的原子版本 | **5.14** | 否则走三步走回退 |
| `demo5` | 5.0 | 只用到基础行为 |

**本项目建议 5.14+**，这样 demo3 走的是原子路径，中间没有窗口。

顺带澄清：**user_notif 不需要 root，也不需要 `CAP_SYS_ADMIN`**。
`Makefile` 里的 `--cap-add SYS_PTRACE` 是为了让 supervisor 读 `/proc/<tid>/mem`，与 user_notif 无关。

---

## 5. 异步坑清单（重点）

这一节是这个项目存在的理由。`USER_NOTIF` 看起来是"同步拦截"，实际上布满了异步语义。

### 坑 1：SEND ≠ 放行

最常见的误解。`SECCOMP_IOCTL_NOTIF_SEND` 的意思是：

> **"别执行了，把这次系统调用的返回值伪造成我给你的这个值。"**

想让内核**真的**执行系统调用，只有一条路：`resp.flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE`。

demo2 里就是这么用的：

```go
// 判定只依赖 domain/type/proto 三个标量 → CONTINUE 安全
n.RespondContinue(req.ID)
```

### 坑 2：`resp.error` 必须是**负数**

内核在 x86 上就是一句 `regs->ax = error ?: val;`。你填 `+EPERM`（=1），
得到的不是"operation not permitted"，而是**系统调用成功返回 1**。

> 实测：`socket()` 返回 `fd=1, err=nil`，然后程序把 stdout 关了，后面的输出全没了。
> 一个符号错误就把"拒绝"变成了"静默放行"，还顺便把 fd 1 送出。
> 填 `-EPERM` 才是对的（`notif.RespondErr` 里做了这件事）。

### 坑 3：只阻塞发起调用的那个线程

`USER_NOTIF` 挂起的是**当前线程**。目标进程里其它线程继续跑，
可以随意修改那块内存、可以继续发别的系统调用、可以 `execve`、可以退出。

这意味着"supervisor 看到的世界"和"syscall 真正执行时的世界"之间**一定有一个时间差**。
你能做的不是消灭它，而是让决策不依赖于它（见坑 4）。

### 坑 4：指针参数 TOCTOU —— CONTINUE 的致命伤

`openat(dirfd, path, flags, mode)`：`seccomp_data` 里 `path` 只是一个地址。
supervisor 要判断路径，只能去 `/proc/<tid>/mem` 读（或 `process_vm_readv`）。

读到的永远是**快照**。而 `CONTINUE` 会让内核**从头重新执行**这次系统调用——
重新从用户内存里读路径。

`demo4` 把这件事演出来了：

```
[payload]    发起 openat("/tmp/lab/allow/ok.txt", O_WRONLY|O_CREAT)
[supervisor] 读到路径 "/tmp/lab/allow/ok.txt"，判定：安全
[attacker]   已把路径改成 "/tmp/lab/deny/pwned.txt"
[supervisor] 回 CONTINUE：批准执行
[payload]    openat 成功，fd=4 实际指向 "/tmp/lab/deny/pwned.txt"
```

supervisor 的日志完美无缺，实际被打开的是被禁止的文件。中间只隔了 800ms 的"裁决耗时"
（真实系统里，一次数据库查询、一次审计上报、一次 GC，都足够）。

结论：

> **只要裁决依赖指针指向的内存，就绝对不能用 CONTINUE。**
> 正确做法是 `ADDFD`：supervisor 按自己读到的快照**亲自执行**（自己 `open`），
> 把结果 fd 注入目标进程。这样"裁决"和"执行"发生在同一侧、同一个字符串上，
> 攻击者改内存只能改变"下一次请求的内容"，改变不了"这一次已经被打开的文件"。
> 更彻底的是 `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`，把路径解析也交给内核原子完成。

### 坑 5：通知用 (id)，不用 (pid)

通知里的 `pid` 其实是 tid。它随时可能消失，也可能被复用。

攻击：supervisor `RECV` 拿到 tid=1234 的通知 → 目标线程被 kill → 系统把 1234 分配给了另一个高权限进程 →
supervisor 按旧通知去 `ADDFD`，把 fd 塞进了错误的对象。

所以任何"动手"之前都要先 `SECCOMP_IOCTL_NOTIF_ID_VALID`。
注意它只能**缩小**窗口，不能消除；真要原子，就用 `ADDFD_FLAG_SEND`（5.14+）。

### 坑 6：supervisor 死了 = 策略静默失效（fail-open）

listener fd 的最后一个引用被关掉之后，所有被拦的系统调用不再挂起，
而是直接返回 **`ENOSYS`**（`demo5` 实测）。

`ENOSYS` 的语义是"这个系统调用不存在"，不是"你被禁止了"：

- 很多程序对 `ENOSYS` 有降级路径（glibc、Go runtime 都有一堆 `..._time64`、`openat2 → openat` 的回退）。
- 没有审计日志、没有告警、没有拒绝——沙箱**悄悄变松**了。
- 目标进程无法区分"内核不支持"和"supervisor 崩了"。

所以：**supervisor 的存活本身就是安全边界**。生产实现要拿 pidfd 盯着它、要 `PR_SET_PDEATHSIG`、
核心策略最好下沉到内核过滤器里（`ERRNO`/`KILL`），USER_NOTIF 只做增强层和审计层。

### 坑 7：listener fd 本身就是权限

谁拿到这个 fd，谁就能裁决——能 `READ` 通知的进程，就能回 `CONTINUE` 或 `EPERM`。
它还能 `dup`、能被 `SCM_RIGHTS` 传给任何人。

- 它默认带 `CLOEXEC`，所以 **`execve` 会自动把它关掉**。这是对的默认值：
  `launcher` 交完 fd 就 `execve(payload)`，不需要（也**不应该**）用
  `fcntl(fd, F_SETFD, 0)` 去清掉 `FD_CLOEXEC`，否则 payload 一启动就继承了裁决权。
  （`execve` 看的是 fd 的 `FD_CLOEXEC` 位，不是 file 的 `f_flags`。）
- 交接只需要一份引用：`SCM_RIGHTS` 传出去的就是同一个 `struct file`，
  supervisor 握着它，通知队列就不会因为 launcher 这边被 `execve` 收走而消失。
- **不要**把它留在不该留的地方。除了"被审的人自己握着钥匙"之外还有个副作用：
  沙箱内进程长期持有 listener 时，supervisor 崩了队列仍活着，
  被拦的 syscall 不会 fail-open 成 `ENOSYS`（demo5 那套），而是**永远挂住**。
- 同一个 listener 允许多个进程同时 `RECV`：通知会被**随机一个**消费者拿走。
  所以一个 listener 只交给**一个**可信 supervisor，不要"多副本高可用"。

### 坑 8：性能与 DoS

- 目标进程每个线程同时只能挂起**一条**通知，supervisor 单线程 `RECV` + 慢处理 = 直接卡死目标。
- 反过来，被监控进程可以疯狂触发被拦的系统调用，把 supervisor 打成日志炸弹（每个 `openat` 一条通知）。
- 所以 USER_NOTIF 只适合拦**低频、高风险**的调用，别拿它拦 `read`/`write`。
- `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`（5.19+）能让等待通知的过程被致命信号打断，
  否则被挂起的线程可能"杀不掉"。

### 坑 9：其它零碎

- `RECV`/`SEND` 会被信号打断（`EINTR`）、目标线程退出（`ENOENT`），循环里要正确处理。
- `RECV`/`SEND` 的 ioctl 参数尺寸随内核演进（历史上出过 `seccomp_notif` 扩容的兼容问题），
  所以 `_IOC` 的 size 必须用 `unsafe.Sizeof` 算，不要抄常量。
- 32 位兼容进程的参数是 32 位的，`args` 高 32 位是垃圾；`openat` 的 `flags` 在内核里是
  `unsigned int`，取低 32 位就够（demo3 的 supervisor 里写了注释）。
- supervisor 自己也该被审计/限制——它是最有权限的那个进程。

### 坑 10：TSYNC 与 NEW_LISTENER 必须补 TSYNC_ESRCH

这条踩过两次，两次都是实测出来的（`--security-opt seccomp=unconfined` 容器内，内核 7.0.14）。
前提仍然是：**goroutine ≠ 线程**——Go 程序刚启动就有 6~7 个 OS 线程
（sysmon、GC worker、netpoller 各占一个），而 seccomp 过滤器是**每线程**的。

**① flags 的位值一位都不能记错。** 对着 `/usr/include/linux/seccomp.h`：

```c
#define SECCOMP_FILTER_FLAG_TSYNC              (1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG                (1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW         (1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER       (1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH        (1UL << 4)   /* 5.7+ */
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)   /* 5.19+ */
```

写错一位的后果不是"不生效"那么明显，而是 **EINVAL 或者悄悄变成另一个语义**：
把 `TSYNC` 写成 `1<<4`，字面上还是"带同步的安装"，实际设的是 `TSYNC_ESRCH`，
**同步压根没开**。而 demo 照样跑得通（`LockOSThread` 兜住了），所以这种 bug 能藏很久——
本仓库早期版本就中过这个招。

**② `NEW_LISTENER` 和 `TSYNC` 确实互斥。** man seccomp(2) 原文：

> If this flag is not set, using **SECCOMP_FILTER_FLAG_NEW_LISTENER** and
> **SECCOMP_FILTER_FLAG_TSYNC** together results in **EINVAL**.

"this flag" 指的是 `TSYNC_ESRCH`。也就是说 5.7+ 想同时要 listener 和"盖住所有线程"，
必须三合一。实测（每次一个独立进程，装完读 `/proc/self/task/*/status`）：

| flags | seccomp() 结果 | 安装后各线程 `Seccomp:` |
|---|---|---|
| `0x0` | 成功，r1=0 | 只有调用线程 =2，其余 0 |
| `0x1` `TSYNC` | 成功，r1=0 | **7 个线程全部 =2** |
| `0x8` `NEW_LISTENER` | 成功，r1=4（listener fd） | 只有调用线程 =2 |
| `0x9` `NEW_LISTENER\|TSYNC` | **EINVAL** | 全部 0 |
| `0x19` `NEW_LISTENER\|TSYNC\|TSYNC_ESRCH` | 成功，r1=4 | **全部 =2** |
| `0x40`（不存在的位） | EINVAL | 全部 0 |

两个要点：**TSYNC 在 Go 进程里是好用的**（早期这节写的"TSYNC 返回 0 但兄弟线程没盖上"
是上面那个位值 bug 的产物，已更正）；而 `NEW_LISTENER` 还必须独占——
同一个线程第二次带它装过滤器会返回 `EBUSY`。

**③ 那为什么仍然要 `LockOSThread()`？** 因为 TSYNC 只解决"安装这一刻已经存在的线程"，
剩下两条路它是救不了的：

1. **TSYNC 失败不设 errno。** 内核把"无法同步的那个线程 tid"当返回值（只有带
   `TSYNC_ESRCH` 才变成 `-ESRCH`）。不带 ESRCH 时，一个正整数返回值既可能是新 fd，
   也可能是肇事 tid，很容易被当成成功。
2. **`execve` 只保留执行它的那个线程的过滤器。** launcher 场景里，装完过滤器后
   goroutine 只要迁移一次，出去的 payload 就是完全没过滤器的裸进程，而且毫无报错。

所以写法是两层保险，缺一不可：

```go
runtime.LockOSThread()                                  // ① 钉住线程
scmp.Install(p, scmp.FlagTSync|scmp.FlagTSyncESRCH, true) // ② 能盖的全盖上
syscall.Socket(...) / syscall.Exec(...)                  // ③ 同一个线程上发
```

三个必须锁线程的地方（本项目全部加了）：

| 位置 | 不锁的后果 |
|---|---|
| demo1/02/05：装完就在主 goroutine 发 syscall | 没带 TSYNC 或同步失败时，goroutine 漂到未过滤线程 → **静默不拦截** |
| demo4：装完立刻发 `openat` | 同上，通知压根不产生，demo 变成"什么都没发生" |
| **launcher：装完 → 传 fd → `execve`** | 即使 TSYNC 成功也救不了：`execve` 只认执行线程 → **payload 完全没有过滤器** |

最后一行最隐蔽：`execve` 是"整个进程只剩一个线程继续跑"的时刻，
选错线程 = 你精心装的沙箱凭空消失，而且全程没有任何报错。

---

## 6. 为什么必须双角色

很多人第一版都会写成 demo2 那样：一个进程里起个 goroutine 当 supervisor。
它能跑通，但它**不是沙箱**，因为：

| 问题 | 后果 |
|---|---|
| 同一个地址空间 | 被监控代码可以 `process_vm_writev` / `ptrace` 改写 supervisor 的策略变量、甚至改跳转 |
| 同一套权限 | 被监控代码可以自己 `open()` 绕过"上报"（过滤器只管它关心的那部分） |
| 同一个线程池/调度器 | supervisor 的 goroutine 可能因为目标进程卡死、死锁、GC 停顿而饿死 |
| 没有崩溃隔离 | 目标进程 `exit_group` 直接把 supervisor 一起带走，剩下的事没人管 |
| 过滤器互相干扰 | 如果用 `TSYNC` 装到了所有线程，supervisor 自己的系统调用也可能命中过滤器 → 自锁 |

正确形态（`demo3` 就是这个）：

```
   supervisor（沙箱外，没有过滤器）          launcher → payload（沙箱内，有过滤器）
   ┌─────────────────────────┐              ┌──────────────────────────────┐
   │ 1. listen /tmp/lab.sock │◀── connect ──│ 2. 装过滤器 NEW_LISTENER      │
   │ 3. recvmsg 收 fd        │◀─ SCM_RIGHTS─│ 4. 把 listener fd 递出去      │
   │ 5. loop RECV            │              │ 6. 保持 CLOEXEC，exec 自动关  │
   │    ├ 读 /proc/tid/mem   │              │ 7. execve(payload)  ← pid 不变│
   │    ├ 策略校验           │              │                              │
   │    └ ADDFD 注入 fd      │── 通知/裁决 ─▶│ payload 只会看到 fd 号        │
   └─────────────────────────┘              └──────────────────────────────┘
```

三个关键设计：

1. **装过滤器的进程和裁决的进程必须分开**，且裁决者在沙箱外、权限与目标解耦。
2. **交接只用 fd**，不用共享内存、不用共享文件——`SCM_RIGHTS` 传的是内核对象引用，
   目标进程之后改什么内存都影响不到已传出去的 listener。
3. **放行动作由 supervisor 完成**（`ADDFD`），而不是"批准 + 让它自己跑"（`CONTINUE`）。

`demo3` 的实测输出（截取）：

```
[recv]  tid=14    openat(dirfd=-100, path=0x243a96268000, flags=0x80241, mode=0644)
[allow] tid=14    路径 "/tmp/lab/allow/hello.txt" 通过策略检查
[allow] tid=14    用 supervisor 的权限打开成功，注入 fd 并把 fd 号回填给目标
成功: /tmp/lab/allow/hello.txt

[recv]  tid=14    openat(dirfd=-100, path=0x243a961fa060, flags=0x80241, mode=0644)
[deny]  tid=14    路径 "/tmp/lab/deny/pwned.txt" 被策略拒绝: 不在白名单目录 /tmp/lab/allow/ 下 -> EPERM
失败（预期就是失败）: open /tmp/lab/deny/pwned.txt: operation not permitted
```

注意 payload 侧完全没有 seccomp 代码——它只是普通地 `os.OpenFile`，
拿到的 fd 甚至是 supervisor 在另一个进程里 `open` 出来的。

`demo3` 里还有两个细节值得留意：

- payload 启动后**主动关掉了**继承来的 listener fd，监控照旧生效，
  因为 supervisor 持有同一个 `struct file` 的另一份引用。这说明"关自己的 fd 解不开监控"。
- 反过来，如果 supervisor 是最后一个持有者并且退出，就退化成 demo5 的 `ENOSYS`。

---

## 7. 项目结构与代码走读

```
docs/flow.md               四张流程图（内核 / 通知生命周期 / 三进程架构 / CONTINUE vs ADDFD）
internal/bpf/bpf.go        cBPF 汇编器：Insn / Fprog / 汇编方法 / 反汇编打印
internal/scmp/scmp.go      常量、结构体、NoNewPrivs、Install（含 TSYNC 细节）
internal/scmp/filter.go    过滤器构造：BlockList / NotifyList / NotifyWriteOpenAt
internal/scmp/arch_*.go    AUDIT_ARCH 与 seccomp 系统调用号（amd64 / arm64）
internal/notif/notif.go    四个 ioctl 的封装 + ADDFD 回退路径
internal/notif/fdpass.go   SCM_RIGHTS 传 fd
internal/notif/mem.go      读 /proc/<tid>/mem 拿 C 字符串
cmd/01-basic               内核态拒绝，观察 EPERM
cmd/02-notify              单进程 USER_NOTIF（反面教材 + CONTINUE 的正确用法）
cmd/03-roles/supervisor    仲裁者（沙箱外）
cmd/03-roles/launcher      装过滤器 + 交接 fd + execve
cmd/03-roles/payload       被监控的业务进程（没有任何 seccomp 代码）
cmd/04-race                CONTINUE 的 TOCTOU 实证
cmd/05-fail-open           listener 关闭后的 ENOSYS
```

几处值得对着看的地方：

- `scmp.Install`：为什么 `NEW_LISTENER` 配 `TSYNC` 必须再补 `TSYNC_ESRCH`，
  以及为什么 `TSYNC` 失败时返回的是"肇事 tid"而不是 errno。
- `scmp.NotifyWriteOpenAt`：只用一条 `AND` 就把"写打开"筛了出来，
  所以 Go runtime 启动时那一堆只读 `openat` 不会打到 supervisor 上。
- `notif.ioctlRecv` 等：ioctl 号是算出来的，`size` 用 `unsafe.Sizeof`。
- `notif.AddfdAndSend`：先试 `ADDFD_FLAG_SEND`（原子），老内核退化成
  `ID_VALID` + `ADDFD` + `SEND`。
- `supervisor.handle`：`AT_FDCWD` 检查、`filepath.Clean` + 前缀、`O_NOFOLLOW`、
  `ID_VALID`，每一步都对应第 5 节里的一个坑。

---

## 8. 生产环境怎么用

- **别自己写 BPF**：用 [libseccomp](https://github.com/seccomp/libseccomp) /
  [`libseccomp-golang`](https://github.com/seccomp/libseccomp-golang)，
  或者 OCI runtime 的 seccomp 配置。它是一个 DSL，能省掉 90% 的踩坑。
  但 libseccomp 的 USER_NOTIF 支持有限，需要精细仲裁时还是要自己 ioctl。
- **默认策略用白名单**：Docker 自带默认 profile 就是"默认 `ERRNO` + 一长串 allow"。
  `--security-opt seccomp=unconfined` 等于关掉这一层。
- **Kubernetes**：`securityContext.seccompProfile.type: RuntimeDefault`（或者 `Localhost` 指向自己的 profile）。
- **黑名单常见项**：`mount` `umount2` `unshare` `setns` `pivot_root` `ptrace` `bpf`
  `keyctl` `add_key` `perf_event_open` `userfaultfd` `io_uring_setup` `kexec_load`
  `open_by_handle_at` `name_to_handle_at` `clone3`（部分 runtime 因兼容性直接返回 ENOSYS）。
- **要路径级控制**，选 `openat2` + `RESOLVE_BENEATH`，或者干脆换 gVisor / Kata / Firecracker。
- **调试**：`strace -f -e trace=seccomp`、`/proc/<pid>/status` 的 `Seccomp*` 字段、
  把动作换成 `RET_LOG` 先观察不拦截。
- **性能**：`CONFIG_SECCOMP_FILTER` + BPF JIT 之后是纳秒级；
  USER_NOTIF 是进程间往返，微秒到毫秒级，别用在热路径。

---

## 9. 参考资料

- `man 2 seccomp`、`man 2 seccomp_unotify`、`man 2 prctl`（`PR_SET_NO_NEW_PRIVS` / `PR_SET_SECCOMP`）
- 内核源码 `kernel/seccomp.c`、`include/uapi/linux/seccomp.h`、`include/linux/seccomp.h`
- LWN: *A seccomp overview*、*Seccomp and user notification*、*The seccomp trap to userspace*
- `tools/testing/selftests/seccomp/seccomp_bpf.c`（内核自带测试，坑最多的细节都在里面）
- 容器侧的参考实现：runc / crun 的 seccomp 部分、moby 的 `profile_default.go`

---

## 附：本机环境说明

Docker Desktop for Mac 用的是一台 LinuxKit 虚拟机，`docker run` 就是真 Linux 内核，
seccomp 全部可用（本项目实测内核 7.0.14）。

想知道自己手上的环境够不够（版本要求见 [4.1 内核版本依赖](#41-内核版本依赖)）：

```bash
docker run --rm --security-opt seccomp=unconfined seccomp-lab sh -c \
  'uname -r; cat /proc/sys/kernel/seccomp/actions_avail'
# 7.0.14-linuxkit
# kill_process kill_thread trap errno user_notif trace log allow
```

`actions_avail` 里出现 `user_notif` 才算能跑 demo2 之后的例子。
发行版大致对照：Ubuntu 22.04 / Debian 12（5.15 / 6.1）全功能；Debian 11（5.10）缺 `ADDFD_FLAG_SEND`，
走三步走回退；Ubuntu 20.04（5.4）没有 `CONTINUE`/`ADDFD`；RHEL 8（4.18）基线没有（发行版可能回移，以 `actions_avail` 为准）。

`Makefile` 里两个额外参数不是可选的：

- `--security-opt seccomp=unconfined`：Docker **自己也用 seccomp**，默认 profile 会给容器挂一层过滤器。
  我们要在容器里再装过滤器，干脆把这层关掉，避免"到底是谁拦的"这种混淆。
- `--cap-add SYS_PTRACE`：supervisor 要读 `/proc/<tid>/mem`，这需要 ptrace 权限
  （很多时候"读不到目标进程内存"就是这个原因，报错是 `EPERM`）。

**IDE 里的红色波浪线不是语法错误。** 这个项目用了 `syscall.SYS_OPENAT`、`syscall.SYS_PRCTL`
这类 **linux-only** 常量，而 IDE 默认用宿主机的 `GOOS=darwin` 做语义分析，于是会报
`undefined: syscall.SYS_OPENAT` / `undefined: AuditArch` 之类——本质是"目标平台选错了"。

仓库里已经带了 `.vscode/settings.json`，把 gopls 的目标平台钉成 linux：

```json
{ "gopls": { "build.env": { "GOOS": "linux", "GOARCH": "amd64" } } }
```

如果还红，重启一下语言服务器（`Go: Restart Language Server`）。用别的 IDE 就等价设置：

| IDE | 设置方式 |
|---|---|
| VS Code / CodeBuddy | 上面的 `.vscode/settings.json`（已包含） |
| GoLand | `Settings → Go → Build Tags & Vendoring → OS = linux / Arch = amd64` |
| 命令行 | `GOOS=linux go build ./...`，或 `make check` |

```bash
make check     # 宿主机上交叉编译 + vet（不需要 Docker，最快的验证方式）
make shell     # 进容器写代码：/lab 里直接 go build ./...
```
