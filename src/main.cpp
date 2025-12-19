/**
 * DNS 服务器 - C++ 实现
 * 
 * DNS (Domain Name System) 是互联网的"电话簿"，负责将域名转换为 IP 地址。
 * 本程序实现了一个基础的 DNS 服务器框架，监听 UDP 2053 端口。
 * 
 * DNS 协议使用 UDP 作为传输层协议（也支持 TCP，但 UDP 更常用）。
 * 标准 DNS 端口是 53，这里使用 2053 是为了避免需要 root 权限。
 */

#include <iostream>      // 标准输入输出流：std::cout, std::cerr, std::endl
#include <cstring>       // C 风格字符串函数：strerror(), memset() 等
#include <sys/socket.h>  // Socket API：socket(), bind(), sendto(), recvfrom()
#include <netinet/in.h>  // Internet 地址结构体：sockaddr_in, htons(), htonl()
#include <unistd.h>      // POSIX API：close() 函数
#include <arpa/inet.h>   // htons(), ntohs() 等网络字节序转换函数
#include <vector>        // std::vector 动态数组

/**
 * DNS 消息头结构体（12 字节）
 * 
 * DNS Header 格式（RFC 1035）：
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |  16 bits
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |  16 bits
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |  16 bits
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |  16 bits
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |  16 bits
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |  16 bits
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct DNSHeader 
{
    uint16_t id;        // 包标识符，响应必须与查询相同
    
    // |QR(1)|OPCODE(4)|AA(1)|TC(1)|RD(1)|RA(1)|Z(3)|RCODE(4)|
    // |  1  |  0000   |  0  |  0  |  0  |  0  | 000|  0000  |
    // 第二个 16 位字段包含多个标志位
    uint16_t flags;     // QR(1) + OPCODE(4) + AA(1) + TC(1) + RD(1) + RA(1) + Z(3) + RCODE(4)
    
    uint16_t qdcount;   // Question Count: 问题部分的条目数
    uint16_t ancount;   // Answer Count: 回答部分的记录数
    uint16_t nscount;   // Authority Count: 授权部分的记录数
    uint16_t arcount;   // Additional Count: 附加部分的记录数
    
    /**
     * 将 DNS Header 序列化为字节数组（网络字节序，大端）
     * 
     * 大端序 vs 小端序示例（以 id = 1234 = 0x04D2 为例）：
     *   - 大端序（网络字节序）: [0x04, 0xD2] 高位字节在前，人类阅读顺序
     *   - 小端序（x86 架构）:   [0xD2, 0x04] 低位字节在前
     * 
     * 网络协议统一使用大端序，所以需要转换。
     * 
     * 序列化后的 12 字节数组布局：
     *   索引:  [0]   [1]   [2]   [3]   [4]   [5]   [6]   [7]   [8]   [9]  [10]  [11]
     *   字段:  |--ID---|  |-flags-|  |qdcount|  |ancount|  |nscount|  |arcount|
     *   示例:  0x04  0xD2  0x80  0x00  0x00  0x00  0x00  0x00  0x00  0x00  0x00  0x00
     *         (id=1234)  (QR=1)   (0)       (0)       (0)       (0)
     */
    std::vector<uint8_t> serialize() const 
    {
        // 创建 12 字节的数组，所有元素初始化为 0
        // DNS Header 固定 12 字节: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
        std::vector<uint8_t> bytes(12);
        
        // ========== ID（16 bits）- 转换为大端序 ==========
        // 示例: id = 1234 = 0x04D2
        // 
        // 提取高字节 (id >> 8) & 0xFF:
        //   1. id = 0x04D2 = 0000 0100 1101 0010 (二进制)
        //   2. id >> 8     = 0000 0000 0000 0100 (右移8位，高8位移到低8位)
        //   3. & 0xFF      = 0000 0000 0000 0100 = 0x04 (掩码保留低8位)
        // 
        // 提取低字节 id & 0xFF:
        //   1. id = 0x04D2 = 0000 0100 1101 0010 (二进制)
        //   2. & 0xFF      = 0000 0000 1101 0010 = 0xD2 (掩码保留低8位)
        // 
        // 结果: bytes[0]=0x04, bytes[1]=0xD2 (大端序：高字节在前)
        bytes[0] = (id >> 8) & 0xFF;   // 高字节: 右移8位取高8位
        bytes[1] = id & 0xFF;          // 低字节: 直接取低8位
        
        // ========== Flags（16 bits）- 转换为大端序 ==========
        // 示例: flags = 0x8000 (QR=1, 其余为0)
        //   bytes[2] = (0x8000 >> 8) & 0xFF = 0x80
        //   bytes[3] = 0x8000 & 0xFF = 0x00
        bytes[2] = (flags >> 8) & 0xFF;
        bytes[3] = flags & 0xFF;
        
        // ========== QDCOUNT（16 bits）==========
        bytes[4] = (qdcount >> 8) & 0xFF;
        bytes[5] = qdcount & 0xFF;
        
        // ========== ANCOUNT（16 bits）==========
        bytes[6] = (ancount >> 8) & 0xFF;
        bytes[7] = ancount & 0xFF;
        
        // ========== NSCOUNT（16 bits）==========
        bytes[8] = (nscount >> 8) & 0xFF;
        bytes[9] = nscount & 0xFF;
        
        // ========== ARCOUNT（16 bits）==========
        bytes[10] = (arcount >> 8) & 0xFF;
        bytes[11] = arcount & 0xFF;
        
        return bytes;
    }
};

/**
 * DNS 消息结构体
 * 包含 header、question、answer、authority、additional 五个部分
 * 目前只实现 header 部分
 */
struct DNSMessage 
{
    DNSHeader header;
    // TODO: 后续添加 question, answer, authority, additional 部分
    
    std::vector<uint8_t> serialize() const 
    {
        return header.serialize();
    }
};

int main() 
{
    // ==================== 1. 初始化输出设置 ====================
    // 设置 std::cout 和 std::cerr 为无缓冲模式
    // std::unitbuf 会在每次输出操作后自动刷新缓冲区
    // 这确保调试信息能够立即显示，而不是等缓冲区满了才输出
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // 禁用 C 标准库的 stdout 缓冲
    // 与上面的设置配合，确保所有输出都是即时的
    setbuf(stdout, NULL);

    // 调试信息，用于确认程序已启动
    std::cout << "Logs from your program will appear here!" << std::endl;

    // ==================== 2. 创建 UDP Socket ====================
    // socket() 函数创建一个通信端点，返回文件描述符
    // 参数说明：
    //   - AF_INET: 使用 IPv4 协议族
    //   - SOCK_DGRAM: 使用数据报套接字（UDP）
    //     * SOCK_STREAM 是 TCP（面向连接、可靠传输）
    //     * SOCK_DGRAM 是 UDP（无连接、不保证可靠）
    //   - 0: 自动选择协议（对于 SOCK_DGRAM 就是 UDP）
    int udpSocket;
    struct sockaddr_in clientAddress;  // 用于存储客户端地址信息

    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) 
    {
        // errno 是全局错误码，strerror() 将其转换为可读的错误信息
        std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
        return 1;
    }

    // ==================== 3. 设置 Socket 选项 ====================
    // SO_REUSEPORT 允许多个 socket 绑定到同一个端口
    // 主要作用：
    //   1. 程序重启时，避免 "Address already in use" 错误
    //      （因为之前的 socket 可能还在 TIME_WAIT 状态）
    //   2. 允许多进程/多线程负载均衡
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) 
    {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    // ==================== 4. 配置服务器地址并绑定 ====================
    // sockaddr_in 结构体用于指定 IPv4 地址
    // 使用 C99 的指定初始化器语法（designated initializers）
    sockaddr_in serv_addr = 
    { 
        .sin_family = AF_INET,           // 地址族：IPv4
        .sin_port = htons(2053),         // 端口号：2053
                                         // htons() = Host TO Network Short
                                         // 将主机字节序转换为网络字节序（大端）
        .sin_addr = { htonl(INADDR_ANY) }, // IP 地址：0.0.0.0（监听所有网卡）
                                           // htonl() = Host TO Network Long
                                           // INADDR_ANY 表示接受来自任何网卡的连接
    };

    // bind() 将 socket 与指定的地址和端口关联
    // 这样内核才知道把发往该端口的数据包交给这个 socket
    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) 
    {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    // ==================== 5. 主循环：接收请求并响应 ====================
    int bytesRead;                              // 接收到的字节数
    char buffer[512];                           // 接收缓冲区
                                                // DNS 消息通常不超过 512 字节（UDP 限制）
    socklen_t clientAddrLen = sizeof(clientAddress);  // 客户端地址结构体的大小

    while (true) 
    {
        // ---------- 5.1 接收 DNS 查询 ----------
        // recvfrom() 从 UDP socket 接收数据
        // 参数说明：
        //   - udpSocket: 要接收数据的 socket
        //   - buffer: 存放接收数据的缓冲区
        //   - sizeof(buffer): 缓冲区大小
        //   - 0: 标志位（无特殊选项）
        //   - clientAddress: [输出] 发送方的地址信息
        //   - clientAddrLen: [输入/输出] 地址结构体的大小
        // 返回值：接收到的字节数，-1 表示错误
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, 
                             reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
        if (bytesRead == -1) 
        {
            perror("Error receiving data");  // perror() 打印错误信息，自动附加 errno 描述
            break;
        }

        // 添加字符串结束符（仅用于调试打印，DNS 数据是二进制的）
        buffer[bytesRead] = '\0';
        std::cout << "Received " << bytesRead << " bytes" << std::endl;

        // ---------- 5.2 构建 DNS 响应 ----------
        // 创建 DNS 响应消息
        DNSMessage response;
        
        // 设置 Header 字段
        response.header.id = 1234;      // 包标识符（测试期望值：1234）
        
        // 构建 flags 字段（16 bits）：
        // QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1) | RA(1) | Z(3) | RCODE(4)
        //   1   |   0000    |   0   |   0   |   0   |   0   | 000  |  0000
        // = 1000 0000 0000 0000 = 0x8000
        uint16_t qr = 1;        // QR = 1 表示这是响应包
        uint16_t opcode = 0;    // OPCODE = 0 标准查询
        uint16_t aa = 0;        // AA = 0 非权威回答
        uint16_t tc = 0;        // TC = 0 未截断
        uint16_t rd = 0;        // RD = 0 不需要递归
        uint16_t ra = 0;        // RA = 0 不支持递归
        uint16_t z = 0;         // Z = 0 保留字段
        uint16_t rcode = 0;     // RCODE = 0 无错误
        
        // 按位组合 flags
        // |QR(1)|OPCODE(4)|AA(1)|TC(1)|RD(1)|RA(1)|Z(3)|RCODE(4)|
        response.header.flags = (qr << 15) | (opcode << 11) | (aa << 10) | 
                                (tc << 9) | (rd << 8) | (ra << 7) | 
                                (z << 4) | rcode;
        
        response.header.qdcount = 0;    // 问题数：0
        response.header.ancount = 0;    // 回答数：0
        response.header.nscount = 0;    // 授权记录数：0
        response.header.arcount = 0;    // 附加记录数：0
        
        // 序列化为字节数组
        std::vector<uint8_t> responseBytes = response.serialize();

        // ---------- 5.3 发送 DNS 响应 ----------
        // sendto() 向指定地址发送 UDP 数据
        // 参数说明：
        //   - udpSocket: 发送数据的 socket
        //   - responseBytes.data(): 要发送的数据指针
        //   - responseBytes.size(): 数据长度（12 字节）
        //   - 0: 标志位
        //   - clientAddress: 目标地址（即发送查询的客户端）
        //   - sizeof(clientAddress): 地址结构体大小
        if (sendto(udpSocket, responseBytes.data(), responseBytes.size(), 0, 
                   reinterpret_cast<struct sockaddr*>(&clientAddress), sizeof(clientAddress)) == -1) 
        {
            perror("Failed to send response");
        }
    }

    // ==================== 6. 清理资源 ====================
    // 关闭 socket，释放系统资源
    close(udpSocket);

    return 0;
}
