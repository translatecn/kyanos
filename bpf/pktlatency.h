//_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")

#pragma GCC diagnostic ignored "-Wint-conversion"

#ifndef __KPROBE_H__
#define __KPROBE_H__

#define PX_AF_UNKNOWN 0xff // 无效或未知的地址族
#define AF_INET 2          // IPv4 地址族
#define AF_INET6 10        // IPv6 地址族
#define MAX_MSG_SIZE 30720 // 最大的消息缓冲区大小为 30,720 字节（30 KB）。
#define EINPROGRESS 115 // 是 POSIX 标准错误码的一种，表示“操作正在进行中”。 见于非阻塞 socket 操作，比如非阻塞连接时
#define MSG_OOB 1       // 发送 高优先级的数据包
#define MSG_PEEK 2      // 在使用 recv() 接收数据时表示窥视数据而不将其从缓冲区移除。

// 描述网络数据包（或请求）在系统中传输的完整生命周期过程 ——
// 从用户空间的应用程序发出请求，一直到通过网络发送出去，并从远端接收到响应
enum step_t {
    start = 0,   // 初始状态
    SSL_OUT,     // 数据被加密（SSL层）
    SYSCALL_OUT, // 用户空间调用系统调用（如 send）
    TCP_OUT,     // 数据进入 TCP 协议处理流程
    IP_OUT,      // 通过 IP 层路由处理
    QDISC_OUT,   // 流量控制/排队规则（例如 Linux 的 qdisc）
    DEV_OUT,     // 准备通过网络设备驱动发送
    NIC_OUT,     // 数据包被发送到网卡（Network Interface Card）
    NIC_IN,      // 接收到远端网卡的数据
    DEV_IN,      // 网络驱动处理接收数据
    IP_IN,       // 数据传到 IP 层
    TCP_IN,      // 数据到达 TCP 层
    USER_COPY,   // 内核空间数据拷贝到用户空间
    SYSCALL_IN,  // 系统调用返回（如 recv）
    SSL_IN,      // 解密收到的数据
    end          // 流程结束
};

enum traffic_protocol_t {
    kProtocolUnset = 0,
    kProtocolUnknown,
    kProtocolHTTP,
    kProtocolHTTP2,
    kProtocolMySQL,
    kProtocolCQL,
    kProtocolPGSQL,
    kProtocolDNS,
    kProtocolRedis,
    kProtocolNATS,
    kProtocolMongo,
    kProtocolKafka,
    kProtocolMux,
    kProtocolAMQP,
    kProtocolRocketMQ,
    kNumProtocols
};

enum endpoint_role_t {
    kRoleClient = 1 << 0,
    kRoleServer = 1 << 1,
    kRoleUnknown = 1 << 2,
};

enum source_function_t {
    kSourceFunctionUnknown,

    // For syscalls.
    kSyscallAccept,
    kSyscallConnect,
    kSyscallClose,
    kSyscallWrite,
    kSyscallRead,
    kSyscallSend,
    kSyscallRecv,
    kSyscallSendTo,
    kSyscallRecvFrom,
    kSyscallSendMsg,
    kSyscallRecvMsg,
    kSyscallSendMMsg,
    kSyscallRecvMMsg,
    kSyscallWriteV,
    kSyscallReadV,
    kSyscallSendfile,

    // For Go TLS libraries.
    kGoTLSConnWrite,
    kGoTLSConnRead,

    // For SSL libraries.
    kSSLWrite,
    kSSLRead,
};

enum conn_trace_state_t {
    unset = 0,            // 未设置：表示当前没有设置连接追踪状态
    traceable,            // 可追踪：连接可以被追踪（可能符合某种协议或者规则）
    protocol_not_matched, // 协议不匹配：连接的协议与预期不一致，无法进行追踪
    protocol_unknown,     // 协议未知：无法识别连接使用的协议
    other,                // 其他：所有无法归类到上述状态的情况
};

enum control_value_index_t {
    // 指定一个 PID（进程 ID）进行监控，常用于测试时排除干扰
    // TODO: 生产环境应采用更健壮的机制，例如：
    // - 支持最多 1024 个 PID 的指定；
    // - 在 BPF 中高效查找以减少性能开销。
    kTargetTGIDIndex = 0, // 目标进程 TGID（通常等于 PID）

    kStirlingTGIDIndex,        // Stirling 本身的进程 ID，用于排除自身影响
    kEnabledXdpIndex,          // 是否启用 XDP（eXpress Data Path）
    kEnableFilterByPid,        // 是否按 PID 过滤
    kEnableFilterByLocalPort,  // 是否按本地端口过滤
    kEnableFilterByRemotePort, // 是否按远程端口过滤
    kEnableFilterByRemoteHost, // 是否按远程 IP 主机过滤
    kSideFilter,               // 端类型过滤：0=全部，1=服务端，2=客户端

    kNumControlValues, // 控制值数量（用于数组大小等场景）

    kTraceProtocol, // 指定要追踪的协议类型，见 traffic_protocol_t 枚举
};

enum message_type_t { kUnknown, kRequest, kResponse };

struct protocol_message_t {
    enum traffic_protocol_t protocol;
    enum message_type_t type;
};

enum traffic_direction_t {
    kEgress,
    kIngress,
};

enum conn_type_t {
    kConnect,       // 连接事件：表示一个新的连接已建立（如 TCP 三次握手完成）
    kClose,         // 关闭事件：表示连接被关闭（如 TCP 四次挥手）
    kProtocolInfer, // 协议推断事件：用于从连接数据中推测所使用的协议
};

struct sock_key {
    uint64_t sip[2]; // 源 IP 地址，128 位，支持 IPv6（IPv4 也可以兼容表示）
    uint64_t dip[2]; // 目的 IP 地址，128 位
    uint16_t sport;  // 源端口
    uint16_t dport;  // 目的端口
};

#define FUNC_NAME_LIMIT 16
#define CMD_LEN 16

struct upid_t {
    union {
        uint32_t pid;
        uint32_t tgid;
    };
    uint64_t start_time_ticks;
};

struct conn_id_t {
    struct upid_t upid; // 唯一进程标识（包括 PID/TGID + 启动时间）
    int32_t fd;         // 网络连接对应的文件描述符
    uint64_t tsid; // 时间戳形式的连接唯一标识符，通常用于区分连接实例（如多个连接复用了同一个 FD）
};

struct conn_id_s_t {
    uint64_t tgid_fd;
    enum conn_trace_state_t no_trace;
};

struct kern_evt {
    char func_name[FUNC_NAME_LIMIT]; // 函数名（事件来源函数），用于调试或标记
    uint64_t ts;                     // 时间戳（事件发生的绝对时间，通常是单调时钟 ns）
    uint32_t ts_delta;               // 与上一个事件的时间差（优化性能/压缩存储）
    uint32_t seq;                    // 序列号（按时间递增，可用于乱序恢复）
    uint32_t len;                    // 数据长度（如网络 payload 长度等）
    uint8_t flags;                   // 事件标志（位字段，描述事件属性）
    bool prepend_length_header;      // 是否在数据前加上长度头（用于 framing）
    uint32_t ifindex;                // 网络接口索引（如 eth0、lo 的编号）
    struct conn_id_s_t conn_id_s; // 连接 ID（标识事件属于哪个连接） ← 结构名疑似应为 `conn_id_t`？
    enum step_t step;             // 当前事件处于哪一步（如 CONNECT、SEND、CLOSE 等状态）
    uint32_t length_header;       // 如果 `prepend_length_header=true`，此字段是实际头部值
};

struct first_packet_evt {
    uint64_t ts;         // 时间戳（通常为首包捕获的时间，单位 ns）
    uint32_t len;        // 数据包长度（payload 的长度或整个报文长度）
    uint8_t flags;       // 标志位（方向、是否丢包、是否有问题等，用于快速分类）
    uint32_t ifindex;    // 网络接口索引（如 eth0, lo，值来自内核）
    enum step_t step;    // 当前连接处于的阶段（如连接建立、协议识别等）
    struct sock_key key; // 连接五元组（源 IP、目标 IP、源端口、目标端口）
};

#define MAX_MSG_SIZE 30720
struct kern_evt_data {
    struct kern_evt ke;
    uint32_t buf_size;
    char msg[MAX_MSG_SIZE];
};

struct kern_evt_ssl_data {
    struct kern_evt ke;   // 通用事件结构，包含时间戳、连接信息、事件状态等元数据
    uint32_t syscall_seq; // 系统调用序列号（用于跟踪读写的顺序，或与对应的调用日志关联）
    uint32_t syscall_len; // 实际系统调用的返回长度（也就是实际读写了多少字节）
    uint32_t buf_size;    // 缓冲区的总大小，即 msg[] 的可用字节数，避免溢出或截断误解
    char msg[MAX_MSG_SIZE]; // 实际读取或写入的数据内容（加密或明文）
};

// struct data_evt {
//   uint64_t tgid_fd;
// };

static inline void my_strcpy(char *dest, const char *src, int n)
{
    int i = 0;
    int LIMIT = n;
    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
        if (i >= LIMIT) {
            i--;
            break;
        }
    }
    dest[i] = '\0';
}

int my_str_ncmp(const char *a, const char *b, int n)
{
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
        if (a[i] == '\0') {
            return 0;
        }
    }
    return 1;
}

struct data_args {
    enum source_function_t source_fn; // 表示哪个函数发起了这次调用（如 write(), sendmsg() 等）
    int sock_event;  // 是否是 socket 相关的调用（1 = 是；0 = 否），用于过滤如 stdout 的 write
    int32_t fd;      // 被调用的文件描述符
    const char *buf; // 指向数据缓冲区（适用于 read / write 类调用）
    const struct iovec *iov; // readv / writev / sendmsg 等的多缓冲区数据
    size_t iovlen;           // iov 数组的长度
    unsigned int *msg_len;   // 专用于 sendmmsg() 等多消息调用，指向每条消息的长度数组
    size_t *ssl_ex_len;      // 可能是 SSL 扩展用的长度信息（比如额外 payload 的长度）
    uint64_t start_ts;       // 系统调用开始的时间戳（ns）
    uint64_t end_ts;         // 系统调用结束的时间戳（ns）
};

struct close_args {
    uint32_t fd;
};

struct sendfile_args {
    int32_t out_fd;    // 目标文件描述符，通常是一个 socket
    int32_t in_fd;     // 源文件描述符，通常是一个文件（如 HTML、图片等）
    size_t count;      // 要发送的数据字节数
    uint64_t start_ts; // 调用开始的时间戳（ns）
    uint64_t end_ts;   // 调用结束的时间戳（ns）
};

struct connect_args {
    const struct sockaddr *addr;
    int32_t fd;
    uint64_t start_ts;
};

struct accept_args {
    struct sockaddr *addr;
    struct socket *sock_alloc_socket;
};

union sockaddr_t {
    struct sockaddr_in6 in6; // IPv6 地址结构
    struct sockaddr_in in4;  // IPv4 地址结构
    struct sockaddr sa;      // 通用 socket 地址结构（用于访问 sa_family 等通用字段）
};

struct conn_info_t {
    struct conn_id_t conn_id; // 唯一连接标识：进程、FD、时间戳
    uint64_t read_bytes;      // 累计读取字节数（明文）
    uint64_t write_bytes;     // 累计写入字节数（明文）
    uint64_t ssl_read_bytes;  // 解密后读取字节数（SSL）
    uint64_t ssl_write_bytes; // 加密前写入字节数（SSL）

    union sockaddr_t laddr; // 本地地址信息（IP + 端口）
    union sockaddr_t raddr; // 远程地址信息

    enum traffic_protocol_t protocol; // 连接中使用的协议类型（HTTP, MySQL 等）
    enum endpoint_role_t role;        // 当前连接端角色（服务端 / 客户端）

    size_t prev_count; // 前一次记录的协议头部长度（如 MySQL/Kafka 等）
    char prev_buf[4];  // 前一次协议头缓存（最多 4 字节）

    bool prepend_length_header; // 是否在数据前插入长度头部（协议解析需求）

    enum conn_trace_state_t no_trace; // 连接是否可被追踪（是否成功识别协议等）
    bool ssl;                         // 是否是加密连接（SSL/TLS）
};

struct conn_evt_t {
    struct conn_info_t conn_info; // 连接的详细信息，包括 PID、FD、字节数、地址、协议、SSL 等状态
    enum conn_type_t conn_type;   // 连接事件类型（连接建立、关闭、协议识别等）
    uint64_t ts;                  // 事件时间戳（通常为单调递增时间，如 ktime_get_ns()）
};

struct parse_kern_evt_body {
    void *ctx;             // 上下文指针，通常指向 eBPF 程序或用户态解析上下文
    u32 inital_seq;        // TCP 数据包的初始序列号，用于流量重组
    struct sock_key *key;  // 指向连接唯一标识的 socket key（源/目的 IP 和端口）
    u32 cur_seq;           // 当前数据包的序列号
    u32 len;               // 当前数据包的有效负载长度（字节数）
    const char *func_name; // 内核函数名称（如 sock_sendmsg 等），用于事件追踪定位
    enum step_t step;      // 当前解析步骤或阶段（例如发送/接收阶段）
    struct tcphdr *tcp;    // 指向 TCP 头部结构体，便于访问 TCP 标志位等信息
    u32 ifindex;           // 网络接口索引，用于标识网卡
};

#define MY_BPF_HASH(name, key_type, value_type)                                                                        \
    struct {                                                                                                           \
        __uint(type, BPF_MAP_TYPE_HASH);                                                                               \
        __uint(key_size, sizeof(key_type));                                                                            \
        __uint(value_size, sizeof(value_type));                                                                        \
        __uint(max_entries, 65535);                                                                                    \
        __uint(map_flags, 0);                                                                                          \
    } name SEC(".maps");

#define MY_BPF_ARRAY_PERCPU(name, value_type)                                                                          \
    struct {                                                                                                           \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                                       \
        __uint(key_size, sizeof(__u32));                                                                               \
        __uint(value_size, sizeof(value_type));                                                                        \
        __uint(max_entries, 1);                                                                                        \
        __uint(map_flags, 0);                                                                                          \
    } name SEC(".maps");

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/ // 以太网标准（IEEE 802.3）起草文件的代号
#define ETH_HLEN 14                                    /* Total octets in header.	 */

#define _(src)                                                                                                         \
    ({                                                                                                                 \
        typeof(src) tmp;                                                                                               \
        bpf_probe_read_kernel(&tmp, sizeof(src), &(src));                                                              \
        tmp;                                                                                                           \
    })

#define _C(src, a, ...) BPF_CORE_READ(src, a, ##__VA_ARGS__)

#define _U(src, a, ...) BPF_PROBE_READ_USER(src, a, ##__VA_ARGS__)

#ifdef BPF_DEBUG
#define pr_bpf_debug(fmt, args...)                                                                                     \
    {                                                                                                                  \
        bpf_printk("nettrace: " fmt "\n", ##args);                                                                     \
    }
#else
#define pr_bpf_debug(fmt, ...)
#endif

#define IP_H_LEN (sizeof(struct iphdr))
#define PROTOCOL_VEC_LIMIT 1
#define LOOP_LIMIT 3

// trace_event_raw_sys_enter
// struct trace_event_raw_sys_enter {
//     struct trace_entry ent;        // 通用 trace 事件头，包含时间戳、CPU ID 等元数据
//     long int id;                   // 系统调用号，标识调用的是哪个系统调用
//     long unsigned int args[6];     // 系统调用的最多6个参数（64位无符号整数数组）
//     char __data[0];                // 可变长数据的占位符（零长度数组，用于灵活扩展）
// };
#define TP_ARGS(dst, idx, ctx)                                                                                         \
    {                                                                                                                  \
        void *__p = (void *)ctx + sizeof(struct trace_entry) + sizeof(long int) + idx * (sizeof(long unsigned int));   \
        bpf_probe_read_kernel(dst, sizeof(*dst), __p);                                                                 \
    }

#define TP_RET(dst, ctx)                                                                                               \
    {                                                                                                                  \
        void *__p = (void *)ctx + sizeof(struct trace_entry) + sizeof(long int);                                       \
        bpf_probe_read_kernel(dst, sizeof(*dst), __p);                                                                 \
    }

// include/net/netfilter/nf_conntrack_tuple.h
struct nf_conntrack_tuple___custom {
    struct nf_conntrack_man src; // 源端地址信息（IP + 端口等）
    struct {
        union nf_inet_addr u3; // 存储目的地址（IPv4 或 IPv6）。
        union {
            __be16 all;
            struct {
                __be16 port;
            } tcp;
            struct {
                __be16 port;
            } udp;
            struct {
                u_int8_t type;
                u_int8_t code;
            } icmp;
            struct {
                __be16 port;
            } dccp;
            struct {
                __be16 port;
            } sctp;
            struct {
                __be16 key;
            } gre;
        } u;
        u_int8_t protonum;
        u_int8_t dir; // 连接方向
    } dst;
} __attribute__((preserve_access_index)); // LLVM 生成的用于保持结构体字段访问信息的标记，支持 CO-RE 动态修正

// include/net/netfilter/nf_conntrack_tuple.h
// 在哈希表中，每个连接都有两个条目：分别对应两种不同的方式。
struct nf_conntrack_tuple_hash___custom {
    struct hlist_nulls_node hnnode;
    struct nf_conntrack_tuple___custom tuple;
} __attribute__((preserve_access_index));

// https://elixir.bootlin.com/linux/v5.2.21/source/include/net/netfilter/nf_conntrack.h
struct nf_conn___older_52 {
    struct nf_conntrack ct_general;
    spinlock_t lock;
    u16 ___cpu;
    struct nf_conntrack_zone zone;
    struct nf_conntrack_tuple_hash___custom tuplehash[IP_CT_DIR_MAX];
} __attribute__((preserve_access_index));

#endif
