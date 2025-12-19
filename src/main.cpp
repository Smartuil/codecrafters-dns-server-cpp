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
#include <string>        // std::string 字符串

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
 * DNS Question 结构体
 * 
 * Question Section 格式：
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     NAME                      |  变长，域名编码
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     TYPE                      |  16 bits，记录类型
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     CLASS                     |  16 bits，记录类别
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 
 * 域名编码示例：
 *   "codecrafters.io" 编码为：
 *   \x0c codecrafters \x02 io \x00
 *   ^^^^ ^^^^^^^^^^^^  ^^^  ^^  ^^
 *   长度12  标签内容   长度2 标签 结束符
 * 
 *   完整字节序列: 0x0C 63 6F 64 65 63 72 61 66 74 65 72 73 02 69 6F 00
 *                     c  o  d  e  c  r  a  f  t  e  r  s     i  o
 */
struct DNSQuestion 
{
    std::string name;    // 域名（如 "codecrafters.io"）
    uint16_t type;       // 记录类型（1 = A 记录，5 = CNAME 等）
    uint16_t qclass;     // 记录类别（1 = IN，互联网）
    
    /**
     * 将域名编码为 DNS 标签序列
     * 
     * 编码规则：
     *   1. 按 '.' 分割域名为多个标签
     *   2. 每个标签格式：<长度字节><内容>
     *   3. 以 \x00 结束
     * 
     * 示例: "codecrafters.io" -> \x0ccodecrafters\x02io\x00
     * 
     * 详细编码过程（以 "codecrafters.io" 为例）：
     * 
     *   输入: "codecrafters.io"
     *         ^^^^^^^^^^^^^  ^^
     *         第一个标签     第二个标签
     * 
     *   步骤1: 找到第一个 '.'，位置 pos=12
     *          标签 "codecrafters"，长度=12 (0x0C)
     *          输出: [0x0C, 'c','o','d','e','c','r','a','f','t','e','r','s']
     * 
     *   步骤2: 从 pos+1=13 开始，找下一个 '.'，未找到
     *          处理最后一个标签 "io"，长度=2 (0x02)
     *          输出: [0x02, 'i','o']
     * 
     *   步骤3: 添加结束符 \x00
     * 
     *   最终结果（十六进制）:
     *   0C 63 6F 64 65 63 72 61 66 74 65 72 73 02 69 6F 00
     *   ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^ ^^^^^ ^^
     *   长度  c  o  d  e  c  r  a  f  t  e  r  s  长度 i  o  结束
     *   =12                                       =2
     */
    static std::vector<uint8_t> encodeDomainName(const std::string& domain) 
    {
        std::vector<uint8_t> encoded;
        size_t start = 0;
        size_t pos = 0;
        
        // 按 '.' 分割域名
        // 示例: domain = "codecrafters.io"
        //       第一次循环: start=0, 找到 pos=12 ('.')
        //       第二次循环: start=13, 找不到 '.', 退出循环
        while ((pos = domain.find('.', start)) != std::string::npos) 
        {
            // 计算当前标签长度
            // 示例: labelLen = 12 - 0 = 12
            size_t labelLen = pos - start;
            
            // 添加长度字节
            // 示例: encoded.push_back(12) -> encoded = [0x0C]
            encoded.push_back(static_cast<uint8_t>(labelLen));
            
            // 添加标签内容
            // 示例: 添加 "codecrafters" 的每个字符
            //       encoded = [0x0C, 'c','o','d','e','c','r','a','f','t','e','r','s']
            for (size_t i = start; i < pos; i++) 
            {
                encoded.push_back(static_cast<uint8_t>(domain[i]));
            }
            
            // 移动到下一个标签的起始位置
            // 示例: start = 12 + 1 = 13
            start = pos + 1;
        }
        
        // 处理最后一个标签（'.' 后面的部分）
        // 示例: start=13, domain.length()=15
        //       最后一个标签 "io", 长度=15-13=2
        if (start < domain.length()) 
        {
            size_t labelLen = domain.length() - start;
            encoded.push_back(static_cast<uint8_t>(labelLen));
            for (size_t i = start; i < domain.length(); i++) 
            {
                encoded.push_back(static_cast<uint8_t>(domain[i]));
            }
        }
        
        // 添加结束符 \x00
        // 最终: encoded = [0x0C, ..., 0x02, 'i', 'o', 0x00]
        encoded.push_back(0x00);
        
        return encoded;
    }
    
    /**
     * 序列化 Question 为字节数组
     */
    std::vector<uint8_t> serialize() const 
    {
        std::vector<uint8_t> bytes;
        
        // 1. 编码域名
        std::vector<uint8_t> encodedName = encodeDomainName(name);
        bytes.insert(bytes.end(), encodedName.begin(), encodedName.end());
        
        // 2. TYPE（2 字节，大端序）
        bytes.push_back((type >> 8) & 0xFF);
        bytes.push_back(type & 0xFF);
        
        // 3. CLASS（2 字节，大端序）
        bytes.push_back((qclass >> 8) & 0xFF);
        bytes.push_back(qclass & 0xFF);
        
        return bytes;
    }
};

/**
 * DNS Answer (Resource Record) 结构体
 * 
 * Answer Section 格式（RFC 1035 Section 3.2.1）：
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     NAME                      |  变长，域名编码
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     TYPE                      |  16 bits，记录类型
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     CLASS                     |  16 bits，记录类别
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     TTL                       |  32 bits，生存时间
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   RDLENGTH                    |  16 bits，RDATA 长度
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    RDATA                      |  变长，记录数据
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 
 * A 记录示例（codecrafters.io -> 8.8.8.8）：
 *   NAME:     \x0ccodecrafters\x02io\x00  (域名编码)
 *   TYPE:     0x0001                       (A 记录)
 *   CLASS:    0x0001                       (IN 互联网)
 *   TTL:      0x0000003C                   (60 秒)
 *   RDLENGTH: 0x0004                       (4 字节)
 *   RDATA:    0x08080808                   (8.8.8.8)
 */
struct DNSAnswer 
{
    std::string name;       // 域名
    uint16_t type;          // 记录类型（1 = A 记录）
    uint16_t aclass;        // 记录类别（1 = IN）
    uint32_t ttl;           // 生存时间（秒）
    uint16_t rdlength;      // RDATA 长度
    std::vector<uint8_t> rdata;  // 记录数据（A 记录为 4 字节 IP 地址）
    
    /**
     * 序列化 Answer 为字节数组
     */
    std::vector<uint8_t> serialize() const 
    {
        std::vector<uint8_t> bytes;
        
        // 1. NAME - 域名编码（复用 DNSQuestion 的编码函数）
        std::vector<uint8_t> encodedName = DNSQuestion::encodeDomainName(name);
        bytes.insert(bytes.end(), encodedName.begin(), encodedName.end());
        
        // 2. TYPE（2 字节，大端序）
        bytes.push_back((type >> 8) & 0xFF);
        bytes.push_back(type & 0xFF);
        
        // 3. CLASS（2 字节，大端序）
        bytes.push_back((aclass >> 8) & 0xFF);
        bytes.push_back(aclass & 0xFF);
        
        // 4. TTL（4 字节，大端序）
        // 示例: ttl = 60 = 0x0000003C
        //   bytes = [0x00, 0x00, 0x00, 0x3C]
        bytes.push_back((ttl >> 24) & 0xFF);  // 最高字节
        bytes.push_back((ttl >> 16) & 0xFF);
        bytes.push_back((ttl >> 8) & 0xFF);
        bytes.push_back(ttl & 0xFF);          // 最低字节
        
        // 5. RDLENGTH（2 字节，大端序）
        bytes.push_back((rdlength >> 8) & 0xFF);
        bytes.push_back(rdlength & 0xFF);
        
        // 6. RDATA（变长）
        // A 记录: 4 字节 IPv4 地址
        // 示例: 8.8.8.8 -> [0x08, 0x08, 0x08, 0x08]
        bytes.insert(bytes.end(), rdata.begin(), rdata.end());
        
        return bytes;
    }
};

/**
 * DNS 消息结构体
 * 包含 header、question、answer、authority、additional 五个部分
 */
struct DNSMessage 
{
    DNSHeader header;
    std::vector<DNSQuestion> questions;  // Question 部分（可包含多个问题）
    std::vector<DNSAnswer> answers;      // Answer 部分（可包含多个回答）
    // TODO: 后续添加 authority, additional 部分
    
    std::vector<uint8_t> serialize() const 
    {
        // 1. 序列化 Header
        std::vector<uint8_t> bytes = header.serialize();
        
        // 2. 序列化所有 Questions
        for (const auto& question : questions) 
        {
            std::vector<uint8_t> questionBytes = question.serialize();
            bytes.insert(bytes.end(), questionBytes.begin(), questionBytes.end());
        }
        
        // 3. 序列化所有 Answers
        for (const auto& answer : answers) 
        {
            std::vector<uint8_t> answerBytes = answer.serialize();
            bytes.insert(bytes.end(), answerBytes.begin(), answerBytes.end());
        }
        
        return bytes;
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
        // 使用 DNSMessage 统一管理响应
        DNSMessage response;
        
        // ===== 设置 Header =====
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
        
        response.header.qdcount = 1;    // 问题数：1
        response.header.ancount = 1;    // 回答数：1（本阶段需要返回 answer）
        response.header.nscount = 0;    // 授权记录数：0
        response.header.arcount = 0;    // 附加记录数：0
        
        // ===== 添加 Question =====
        DNSQuestion question;
        question.name = "codecrafters.io";  // 域名
        question.type = 1;                   // TYPE = 1 (A 记录)
        question.qclass = 1;                 // CLASS = 1 (IN，互联网)
        response.questions.push_back(question);
        
        // ===== 添加 Answer =====
        DNSAnswer answer;
        answer.name = "codecrafters.io";    // 域名（与 Question 相同）
        answer.type = 1;                     // TYPE = 1 (A 记录)
        answer.aclass = 1;                   // CLASS = 1 (IN，互联网)
        answer.ttl = 60;                     // TTL = 60 秒
        answer.rdlength = 4;                 // RDATA 长度 = 4 字节（IPv4 地址）
        // RDATA: IP 地址 8.8.8.8
        // 每个数字占 1 字节: [8, 8, 8, 8] = [0x08, 0x08, 0x08, 0x08]
        answer.rdata = {8, 8, 8, 8};
        response.answers.push_back(answer);
        
        // ===== 序列化响应 =====
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
