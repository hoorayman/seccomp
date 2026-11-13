# 流程图总览

文字看晕了就看图。这份文档把项目拆成四张图，对应四个不同的层次：

| 图 | 层次 | 回答的问题 |
|---|---|---|
| [图 1](#图-1全景一次系统调用在内核里遇到什么) | 内核 | 系统调用是在哪里被拦下的？拦下来有几种结局？ |
| [图 2](#图-2一条通知的生命周期) | ioctl 协议 | RECV / SEND / ADDFD 之间是什么关系？ |
| [图 3](#图-3demo3-的三进程部署与-fd-的流动) | 进程架构 | 为什么必须有 supervisor？fd 是怎么交过去的？ |
| [图 4](#图-4为什么-continue-会死addfd-不会) | 安全结论 | CONTINUE 和 ADDFD 的本质区别 |

四步口诀：**装（Install）→ 拦（过滤器）→ 判（supervisor）→ 办（ADDFD）**。

> 内核版本要求（USER_NOTIF 5.0 / CONTINUE 5.5 / ADDFD 5.9 / ADDFD_FLAG_SEND 5.14）
> 见 [README 4.1 内核版本依赖](../README.md#41-内核版本依赖)。

---

## 图 1：全景，一次系统调用在内核里遇到什么

```
 用户态                     ┌───────────────────────── 内核 ─────────────────────────┐
                           │                                                        │
  socket() ──── syscall ──▶│  ① 进入 __secure_computing()                           │
                           │        │                                               │
                           │        ▼                                               │
                           │  ② 跑过滤器链（每个线程一条链表，多层的取最严动作）      │
                           │     filterN → ... → filter1  (cBPF，只读 seccomp_data) │
                           │        │                                               │
                           │        ├─ ALLOW ──────▶ ③ 真的执行 socket，返回 fd      │
                           │        ├─ ERRNO ──────▶ ③ 跳过执行，返回 -EPERM (demo1) │
                           │        ├─ KILL ───────▶ ③ 杀进程                        │
                           │        └─ USER_NOTIF ─▶ ④ 挂起线程 + 塞进队列 ──┐       │
                           │                                                  │       │
                           └──────────────────────────────────────────────────┼───────┘
                                                                              │
                                                          listener fd 上的队列
                                                                              │
                           ┌──────────────────────────────────────────────────┘
                           ▼
              supervisor（沙箱外）：RECV → 判 → SEND / ADDFD
```

**关键认知**：②那一步只看得见 `nr / arch / args[6]` 这些**原始数字**。`openat` 的路径对它来说只是"地址 `0x243a96268000`"，所以**内核层不可能做路径级策略**——这就注定了 ④ 必须存在。

对应代码：`internal/scmp/filter.go`（生成 ②）、`internal/scmp/scmp.go:Install`（装 ② 的入口）。

---

## 图 2：一条通知的生命周期

```
                  目标线程被挂起（睡在内核里，什么也干不了）
                                │
                                ▼
                    ┌──────────────────────┐
                    │ 排队中（内核队列）   │
                    └──────────┬───────────┘
                               │ ioctl RECV
                               ▼
                    ┌──────────────────────┐
                    │ 已取走（你有 id 了） │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
        ID_VALID 失败     决策阶段            （可选）
        → ENOENT，丢弃   读 /proc/<tid>/mem
              │          查策略、自己 open
              │                │
              │    ┌───────────┼───────────┐
              │    ▼           ▼           ▼
              │  拒绝        代劳        批准
              │  SEND      ADDFD{SEND}   SEND{CONTINUE}
              │  Error=-EPERM  Val=newfd     │
              │    │           │           │
              └────┴───────────┴───────────┘
                               │
                               ▼
              内核销毁通知 + 唤醒线程 + 返回 val/error
```

**关键认知**：**RECV 和 SEND 必须配对**。只 RECV 不 SEND，线程永远挂着；SEND 之后这条通知就销毁了，没有任何"再想想"的机会。三种结局都是"发一条 `NotifResp`"，区别只在字段怎么填。

对应代码：`internal/notif/notif.go`（`Receive` / `Send` / `IDValid` / `AddfdAndSend`）。

---

## 图 3：demo3 的三进程部署与 fd 的流动

> 下面的 fd / pid 编号是某次真实运行的示意，你本机跑出来的数字会不同。

```
 ① supervisor 先起来（没有过滤器，想看什么看什么）
    ┌───────────────────────────┐
    │ supervisor   pid 12       │
    │ listen /tmp/lab/sup.sock  │
    └───────────┬───────────────┘
                │ ② accept
                │                              ③ connect
                │        ┌──────────────────────────────────┐
                │        │ launcher  pid 13                 │
                │◀───────┤ ④ seccomp(NEW_LISTENER) → fd 4   │
                │  fd 5  │ ⑤ sendmsg(SCM_RIGHTS, fd 4)       │
                │ (dup)  │ ⑥ 保持 CLOEXEC，exec 自动关      │
                │        │ ⑦ execve(payload)  ← pid 不变     │
                │        └──────────────┬───────────────────┘
                │                       │ execve
                │        ┌──────────────▼───────────────────┐
                │        │ payload  pid 13（还是 13！）     │
                │        │ 继承过滤器，但 fd 4 已被 exec 关 │
                │        └──────────────┬───────────────────┘
                │                       │ os.OpenFile(..., O_WRONLY|O_CREAT)
                │                       ▼
                │              ⑧ 内核挂起，入队
                │◀──────────────────────┘
                │ ⑨ RECV
                │ ⑩ 读 /proc/13/mem 拿路径
                │ ⑪ 校验白名单
                │ ⑫ 自己 open(allow.txt)  ← 用 supervisor 的权限
                │ ⑬ ADDFD(注入) + Val=3
                └──────────────────────────────────────▶ payload 的 openat 返回 3
```

**关键认知**：launcher / supervisor 两边持有的是**同一个内核对象的两份引用**（fd 号不同），
交接完 launcher 那份被 `execve` 收走（CLOEXEC），所以最后只剩 supervisor 一份——
它一关，被拦的 syscall 全部 `ENOSYS`（demo5）。裁决权自始至终没进过沙箱。

对应代码：`cmd/03-roles/{supervisor,launcher,payload}/main.go`、`internal/notif/fdpass.go`。

---

## 图 4：为什么 `CONTINUE` 会死，`ADDFD` 不会

```
【CONTINUE · demo4】
 目标线程  openat(buf = "/lab/allow/ok.txt")
              │挂起
 内核        └─── 通知 ──▶  supervisor
                              │ 读 /proc/mem → "allow/ok.txt" ✓ 判定安全
                              │ ⏳ 800ms（查数据库/写审计/GC 停顿）
                    攻击线程 ─┤ 改同一块内存 → "/lab/deny/pwned.txt"
                              │
                              └─── SEND CONTINUE ──▶ 内核
                                                       │ 重新执行 openat
                                                       │ 重新读内存 ← 已变！
                                                       ▼
                                              打开了 deny/pwned.txt
                              ❌ 日志说批了 A，实际做了 B

【ADDFD · demo3】
 目标线程  openat(buf = "/lab/allow/ok.txt")
              │挂起
 内核        └─── 通知 ──▶  supervisor
                              │ 读 /proc/mem → "allow/ok.txt" ✓
                    攻击线程 ─┤ 改内存（无所谓）
                              │ 我把这个字符串自己 open()  ← 办完了！
                              └─── ADDFD(真 fd) ──▶ 内核 ──▶ 目标拿到真 fd
                              ✅ 攻击者只能影响"下一次请求"
```

**一句话**：`CONTINUE` 是"我批准，你去办"；`ADDFD` 是"我办好了，这是凭证"。**裁决和执行必须在同一侧发生。**

对应代码：`cmd/04-race/main.go`（反面）、`cmd/03-roles/supervisor/main.go:handle`（正面）。

---

## 四步对应到代码

```
装  internal/scmp/scmp.go      Install()          PR_SET_NO_NEW_PRIVS + TSYNC
    internal/bpf/bpf.go        Prog / Fprog       生成 cBPF 字节码
拦  internal/scmp/filter.go    BlockList()        表驱动：只比 syscall 号
                               NotifyWriteOpenAt() 手写：能看 flags 参数
判  internal/notif/mem.go      ReadCString()      /proc/<tid>/mem 读快照
    internal/notif/notif.go    IDValid()          事前体检（缩小窗口，不是保证）
办  internal/notif/notif.go    AddfdAndSend()     代劳（安全）
                               RespondErr()       拒绝
                               RespondContinue()  批准（危险）
```

## demo 与图的对应关系

| demo | 演示的是 |
|---|---|
| `01-basic` | 图 1 的 `ERRNO` 分支 |
| `02-notify` | 图 2 的完整状态机（但用错了架构） |
| `03-roles` | 图 3 + 图 4 下半（正确姿势） |
| `04-race` | 图 4 上半（错误姿势的后果） |
| `05-fail-open` | 图 3 最后一份引用消失之后 |

---

文字版原理见 [README](../README.md) 第 3、5、6 节。
