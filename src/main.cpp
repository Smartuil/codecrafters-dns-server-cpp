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
     * 从字节数组解析 DNS Header（反序列化）
     * 
     * @param data 原始字节数据（至少 12 字节）
     * @return 解析后的 DNSHeader
     * 
     * ============================================================
     * 完整解析示例：假设收到以下 12 字节的 DNS 请求头
     * ============================================================
     * 
     * 原始字节（十六进制）：
     *   索引:  [0]   [1]   [2]   [3]   [4]   [5]   [6]   [7]   [8]   [9]  [10]  [11]
     *   数据:  0x04  0xD2  0x01  0x00  0x00  0x01  0x00  0x00  0x00  0x00  0x00  0x00
     *          |--ID---|  |-flags-|  |qdcount|  |ancount|  |nscount|  |arcount|
     * 
     * ---------- 1. 解析 ID（字节 0-1）----------
     * 
     *   data[0] = 0x04 = 0000 0100
     *   data[1] = 0xD2 = 1101 0010
     * 
     *   计算过程：(data[0] << 8) | data[1]
     *   
     *   步骤 1: data[0] << 8
     *           0x04 << 8 = 0x0400
     *           二进制: 0000 0100 0000 0000
     *   
     *   步骤 2: | data[1]
     *           0x0400 | 0xD2 = 0x04D2
     *           二进制: 0000 0100 0000 0000
     *                 | 0000 0000 1101 0010
     *                 = 0000 0100 1101 0010
     *   
     *   结果: id = 0x04D2 = 1234
     * 
     * ---------- 2. 解析 Flags（字节 2-3）----------
     * 
     *   data[2] = 0x01 = 0000 0001
     *   data[3] = 0x00 = 0000 0000
     * 
     *   计算过程：(data[2] << 8) | data[3]
     *   
     *   步骤 1: data[2] << 8
     *           0x01 << 8 = 0x0100
     *   
     *   步骤 2: | data[3]
     *           0x0100 | 0x00 = 0x0100
     *   
     *   结果: flags = 0x0100 = 0000 0001 0000 0000
     *   
     *   Flags 位布局（从高位到低位）：
     *   |QR|  OPCODE |AA|TC|RD|RA|  Z  | RCODE |
     *   |15| 14-11   |10| 9| 8| 7| 6-4 |  3-0  |
     *   | 0| 0 0 0 0 | 0| 0| 1| 0| 0 0 0| 0 0 0 0|
     *   
     *   解析各字段：
     *     - QR     = (0x0100 >> 15) & 0x01 = 0  （这是查询）
     *     - OPCODE = (0x0100 >> 11) & 0x0F = 0  （标准查询）
     *     - AA     = (0x0100 >> 10) & 0x01 = 0  （非权威）
     *     - TC     = (0x0100 >> 9)  & 0x01 = 0  （未截断）
     *     - RD     = (0x0100 >> 8)  & 0x01 = 1  （期望递归）
     *     - RA     = (0x0100 >> 7)  & 0x01 = 0  （不支持递归）
     *     - Z      = (0x0100 >> 4)  & 0x07 = 0  （保留）
     *     - RCODE  = 0x0100 & 0x0F = 0          （无错误）
     * 
     * ---------- 3. 解析 QDCOUNT（字节 4-5）----------
     * 
     *   data[4] = 0x00, data[5] = 0x01
     *   qdcount = (0x00 << 8) | 0x01 = 0x0001 = 1
     *   含义：有 1 个问题
     * 
     * ---------- 4. 解析 ANCOUNT（字节 6-7）----------
     * 
     *   data[6] = 0x00, data[7] = 0x00
     *   ancount = (0x00 << 8) | 0x00 = 0x0000 = 0
     *   含义：有 0 个回答（查询请求通常为 0）
     * 
     * ---------- 5. 解析 NSCOUNT（字节 8-9）----------
     * 
     *   data[8] = 0x00, data[9] = 0x00
     *   nscount = 0
     * 
     * ---------- 6. 解析 ARCOUNT（字节 10-11）----------
     * 
     *   data[10] = 0x00, data[11] = 0x00
     *   arcount = 0
     * 
     * ============================================================
     * 最终解析结果
     * ============================================================
     *   id      = 1234   (0x04D2)
     *   flags   = 256    (0x0100) -> QR=0, OPCODE=0, RD=1
     *   qdcount = 1      (1 个问题)
     *   ancount = 0      (0 个回答)
     *   nscount = 0
     *   arcount = 0
     */
    static DNSHeader parse(const uint8_t* data)
    {
        DNSHeader header;
        
        // ID（2 字节，大端序）: 高字节在前，低字节在后
        // 示例: [0x04, 0xD2] -> (0x04 << 8) | 0xD2 = 0x04D2 = 1234
        header.id = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        
        // Flags（2 字节，大端序）
        // 示例: [0x01, 0x00] -> (0x01 << 8) | 0x00 = 0x0100
        header.flags = (static_cast<uint16_t>(data[2]) << 8) | data[3];
        
        // QDCOUNT（2 字节）
        // 示例: [0x00, 0x01] -> 1
        header.qdcount = (static_cast<uint16_t>(data[4]) << 8) | data[5];
        
        // ANCOUNT（2 字节）
        header.ancount = (static_cast<uint16_t>(data[6]) << 8) | data[7];
        
        // NSCOUNT（2 字节）
        header.nscount = (static_cast<uint16_t>(data[8]) << 8) | data[9];
        
        // ARCOUNT（2 字节）
        header.arcount = (static_cast<uint16_t>(data[10]) << 8) | data[11];
        
        return header;
    }
    
    /**
     * 从 flags 中提取 OPCODE（4 bits，位 14-11）
     * 
     * Flags 位布局: |QR(15)|OPCODE(14-11)|AA(10)|TC(9)|RD(8)|RA(7)|Z(6-4)|RCODE(3-0)|
     * 
     * 提取示例（flags = 0x0100 = 0000 0001 0000 0000）：
     *   步骤 1: flags >> 11
     *           0000 0001 0000 0000 >> 11 = 0000 0000 0000 0000 = 0
     *   步骤 2: & 0x0F (保留低 4 位)
     *           0 & 0x0F = 0
     *   结果: OPCODE = 0 (标准查询)
     * 
     * 另一示例（flags = 0x7800，OPCODE=15）：
     *   0111 1000 0000 0000 >> 11 = 0000 0000 0000 1111 = 15
     *   15 & 0x0F = 15
     */
    uint8_t getOpcode() const { return (flags >> 11) & 0x0F; }
    
    /**
     * 从 flags 中提取 RD（1 bit，位 8）
     * 
     * 提取示例（flags = 0x0100 = 0000 0001 0000 0000）：
     *   步骤 1: flags >> 8
     *           0000 0001 0000 0000 >> 8 = 0000 0000 0000 0001 = 1
     *   步骤 2: & 0x01 (保留最低 1 位)
     *           1 & 0x01 = 1
     *   结果: RD = 1 (期望递归查询)
     */
    uint8_t getRD() const { return (flags >> 8) & 0x01; }
    
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
     * 从字节数组解析 DNS Question（反序列化）- 支持压缩
     * 
     * @param data 原始字节数据（完整的 DNS 消息，从头开始）
     * @param offset [输入/输出] 当前解析位置，解析完成后更新为下一个位置
     * @return 解析后的 DNSQuestion
     * 
     * ============================================================
     * DNS 消息压缩机制（RFC 1035 Section 4.1.4）
     * ============================================================
     * 
     * 压缩原理：
     *   为了减少消息大小，DNS 允许使用"指针"来引用之前出现过的域名。
     *   指针是一个 2 字节的值，格式如下：
     *   
     *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *   | 1  1|                OFFSET                   |
     *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *   
     *   - 高 2 位为 11（0xC0）表示这是一个指针
     *   - 低 14 位是从消息开头的偏移量
     * 
     * 判断方法：
     *   - 普通标签: 长度字节 < 64 (0x00-0x3F)，高 2 位为 00
     *   - 压缩指针: 长度字节 >= 192 (0xC0-0xFF)，高 2 位为 11
     * 
     * ============================================================
     * 压缩示例
     * ============================================================
     * 
     * 假设消息中有两个问题：
     *   Question 1: "codecrafters.io"
     *   Question 2: "abc.codecrafters.io"（压缩）
     * 
     * 原始字节布局：
     *   [0-11]  Header (12 bytes)
     *   [12]    0x0C (长度=12)
     *   [13-24] "codecrafters"
     *   [25]    0x02 (长度=2)
     *   [26-27] "io"
     *   [28]    0x00 (结束)
     *   [29-30] TYPE (0x0001)
     *   [31-32] CLASS (0x0001)
     *   
     *   Question 2 (使用压缩):
     *   [33]    0x03 (长度=3)
     *   [34-36] "abc"
     *   [37-38] 0xC0 0x0C (指针，指向偏移 12，即 "codecrafters.io")
     *   [39-40] TYPE (0x0001)
     *   [41-42] CLASS (0x0001)
     * 
     * 解析 Question 2:
     *   1. 读取 [33] = 0x03，这是普通标签，长度=3
     *   2. 读取 "abc"
     *   3. 读取 [37] = 0xC0，高 2 位为 11，这是压缩指针
     *   4. 计算偏移: (0xC0 & 0x3F) << 8 | 0x0C = 0x000C = 12
     *   5. 跳转到偏移 12，继续解析 "codecrafters.io"
     *   6. 最终得到: "abc.codecrafters.io"
     */
    static DNSQuestion parse(const uint8_t* data, size_t& offset)
    {
        DNSQuestion question;
        
        // 解析域名（支持压缩）
        question.name = parseDomainName(data, offset);
        
        // ========== 解析 TYPE（2 字节，大端序）==========
        question.type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
        
        // ========== 解析 CLASS（2 字节，大端序）==========
        question.qclass = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
        
        return question;
    }
    
    /**
     * 解析域名（支持压缩指针）
     * 
     * @param data 完整的 DNS 消息数据
     * @param offset [输入/输出] 当前位置，解析后更新（注意：遇到指针时只前进 2 字节）
     * @return 解析后的域名字符串
     * 
     * ============================================================
     * 压缩指针偏移量计算详解
     * ============================================================
     * 
     * 压缩指针格式（2 字节）：
     *   字节1: [1 1 X X X X X X]  字节2: [Y Y Y Y Y Y Y Y]
     *          ↑ ↑ └────┬────┘          └──────┬──────┘
     *        标志位   高6位               低8位
     *                 └──────────┬──────────┘
     *                       14位偏移量
     * 
     * 公式: offset = ((byte1 & 0x3F) << 8) | byte2
     * 
     * ---------- 示例 1: 指针 0xC0 0x0C（偏移 12）----------
     * 
     *   字节1: 0xC0 = 1100 0000
     *   字节2: 0x0C = 0000 1100
     * 
     *   步骤 1: 0xC0 & 0x3F（去掉标志位，保留低6位）
     *           1100 0000
     *         & 0011 1111
     *         ───────────
     *           0000 0000 = 0x00
     * 
     *   步骤 2: 0x00 << 8（左移8位，为低8位腾出空间）
     *           0x00 << 8 = 0x0000
     * 
     *   步骤 3: 0x0000 | 0x0C（合并低8位）
     *           0000 0000 0000 0000
     *         | 0000 0000 0000 1100
     *         ─────────────────────
     *           0000 0000 0000 1100 = 0x000C = 12
     * 
     *   结果: 偏移量 = 12
     * 
     * ---------- 示例 2: 指针 0xC1 0x2F（偏移 303）----------
     * 
     *   字节1: 0xC1 = 1100 0001
     *   字节2: 0x2F = 0010 1111
     * 
     *   步骤 1: 0xC1 & 0x3F = 0000 0001 = 0x01
     *   步骤 2: 0x01 << 8   = 0x0100 = 256
     *   步骤 3: 0x0100 | 0x2F = 0x012F = 303
     * 
     *   结果: 偏移量 = 303
     * 
     * 注意: 14位偏移量最大可表示 2^14 - 1 = 16383 字节
     */
    static std::string parseDomainName(const uint8_t* data, size_t& offset)
    {
        std::string name;
        bool jumped = false;      // 是否已经跳转过（用于正确更新 offset）
        size_t jumpOffset = 0;    // 跳转前的位置
        size_t currentPos = offset;
        
        while (true)
        {
            uint8_t labelLen = data[currentPos];
            
            // 检查是否是压缩指针（高 2 位为 11，即 >= 0xC0）
            // 判断方法: labelLen & 0xC0 == 0xC0
            //   0xC0 = 1100 0000，与操作后如果高2位是11，结果仍为0xC0
            if ((labelLen & 0xC0) == 0xC0)
            {
                // 这是一个压缩指针
                // 指针格式: [11XXXXXX] [YYYYYYYY] (2 bytes)
                //           ^^标志位   低14位是偏移量
                if (!jumped)
                {
                    // 第一次跳转，记录原始位置 + 2（指针占 2 字节）
                    jumpOffset = currentPos + 2;
                    jumped = true;
                }
                
                // 计算指针指向的偏移量
                // ((labelLen & 0x3F) << 8) | data[currentPos + 1]
                //   1. labelLen & 0x3F: 清除高2位标志位，保留低6位
                //   2. << 8: 左移8位，为低8位腾出空间
                //   3. | data[currentPos + 1]: 合并第二个字节（低8位）
                uint16_t pointer = ((labelLen & 0x3F) << 8) | data[currentPos + 1];
                currentPos = pointer;  // 跳转到指针指向的位置
                continue;
            }
            
            // 长度为 0 表示域名结束
            if (labelLen == 0)
            {
                currentPos++;  // 跳过结束符
                break;
            }
            
            // 普通标签
            currentPos++;  // 跳过长度字节
            
            // 如果不是第一个标签，添加分隔符 '.'
            if (!name.empty())
            {
                name += '.';
            }
            
            // 读取标签内容
            for (uint8_t i = 0; i < labelLen; i++)
            {
                name += static_cast<char>(data[currentPos]);
                currentPos++;
            }
        }
        
        // 更新 offset
        // 如果发生了跳转，offset 应该指向指针之后（指针占 2 字节）
        // 如果没有跳转，offset 应该指向域名结束符之后
        if (jumped)
        {
            offset = jumpOffset;
        }
        else
        {
            offset = currentPos;
        }
        
        return name;
    }
    
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
     * 从字节数组解析 DNS Answer（反序列化）
     * 
     * @param data 完整的 DNS 消息数据
     * @param offset [输入/输出] 当前解析位置
     * @return 解析后的 DNSAnswer
     */
    static DNSAnswer parse(const uint8_t* data, size_t& offset)
    {
        DNSAnswer answer;
        
        // 1. 解析域名（支持压缩）
        answer.name = DNSQuestion::parseDomainName(data, offset);
        
        // 2. TYPE（2 字节，大端序）
        answer.type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
        
        // 3. CLASS（2 字节，大端序）
        answer.aclass = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
        
        // 4. TTL（4 字节，大端序）
        answer.ttl = (static_cast<uint32_t>(data[offset]) << 24) |
                     (static_cast<uint32_t>(data[offset + 1]) << 16) |
                     (static_cast<uint32_t>(data[offset + 2]) << 8) |
                     data[offset + 3];
        offset += 4;
        
        // 5. RDLENGTH（2 字节，大端序）
        answer.rdlength = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
        
        // 6. RDATA（rdlength 字节）
        answer.rdata.assign(data + offset, data + offset + answer.rdlength);
        offset += answer.rdlength;
        
        return answer;
    }
    
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

/**
 * 向上游 DNS 服务器转发查询并获取响应
 * 
 * @param resolverAddr 上游 DNS 服务器地址
 * @param question 要查询的问题
 * @param queryId 查询 ID
 * @return 从上游服务器获取的 Answer
 * 
 * ============================================================
 * DNS 转发完整流程示例
 * ============================================================
 * 
 * 场景：客户端查询 "abc.example.com" 和 "xyz.example.com"
 *       转发服务器配置为 --resolver 8.8.8.8:53
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                           整体数据流                                         │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * 
 *   ┌──────────┐         ┌──────────────────┐         ┌─────────────────┐
 *   │  Client  │ ──(1)──>│  DNS Forwarder   │ ──(2)──>│  Upstream DNS   │
 *   │ (Tester) │         │  (本程序:2053)    │         │  (8.8.8.8:53)   │
 *   └──────────┘         └──────────────────┘         └─────────────────┘
 *        │                       │                           │
 *        │   请求: 2个问题        │                           │
 *        │   ID=1234             │   转发请求1: abc.example.com
 *        │                       │   ID=1234                 │
 *        │                       │ ─────────────────────────>│
 *        │                       │                           │
 *        │                       │   响应1: 1.2.3.4          │
 *        │                       │ <─────────────────────────│
 *        │                       │                           │
 *        │                       │   转发请求2: xyz.example.com
 *        │                       │   ID=1234                 │
 *        │                       │ ─────────────────────────>│
 *        │                       │                           │
 *        │                       │   响应2: 5.6.7.8          │
 *        │                       │ <─────────────────────────│
 *        │                       │                           │
 *        │   合并响应: 2个答案    │                           │
 *        │   ID=1234             │                           │
 *        │ <─────────────────────│                           │
 *        │                       │                           │
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 步骤 1: 客户端发送请求到转发服务器 (端口 2053)                                │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * 
 *   客户端请求（包含 2 个问题）：
 *   
 *   Header (12 bytes):
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         ID = 1234 (0x04D2)        |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |QR=0|OP=0|AA|TC|RD=1|RA|Z|RCODE=0  |  Flags = 0x0100
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         QDCOUNT = 2               |  2 个问题
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         ANCOUNT = 0               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         NSCOUNT = 0               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         ARCOUNT = 0               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   
 *   Question 1: abc.example.com
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   | 3|a |b |c | 7|e |x |a |m |p |l |e |  \x03abc\x07example\x03com\x00
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   | 3|c |o |m | 0|           TYPE=1   |  TYPE = A
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         CLASS = 1 (IN)            |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   
 *   Question 2: xyz.example.com (使用压缩指针)
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   | 3|x |y |z |0xC0|0x10|  TYPE=1     |  \x03xyz + 指针(指向 offset 16)
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         CLASS = 1 (IN)            |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 步骤 2: 转发服务器解析请求                                                   │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * 
 *   1. 解析 Header:
 *      - ID = 1234
 *      - QDCOUNT = 2 (有 2 个问题)
 *      - RD = 1 (期望递归)
 *   
 *   2. 解析 Question 1:
 *      - 读取 \x03abc -> "abc"
 *      - 读取 \x07example -> "example"
 *      - 读取 \x03com -> "com"
 *      - 读取 \x00 -> 结束
 *      - 结果: name = "abc.example.com"
 *   
 *   3. 解析 Question 2 (带压缩):
 *      - 读取 \x03xyz -> "xyz"
 *      - 读取 0xC0 0x10 -> 压缩指针，偏移 = 16
 *      - 跳转到 offset 16，继续读取 "example.com"
 *      - 结果: name = "xyz.example.com"
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 步骤 3: 分别转发每个问题到上游 DNS (因为上游只接受单个问题)                    │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * 
 *   转发请求 1 (abc.example.com):
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         ID = 1234                 |  保持原 ID
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         Flags = 0x0100 (RD=1)     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         QDCOUNT = 1               |  只有 1 个问题！
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |    Question: abc.example.com      |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   
 *   上游响应 1:
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         ID = 1234                 |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         ANCOUNT = 1               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |    Answer: abc.example.com        |
 *   |    TYPE=A, CLASS=IN, TTL=300      |
 *   |    RDATA = 1.2.3.4                |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   
 *   转发请求 2 (xyz.example.com): 同样流程...
 *   上游响应 2: RDATA = 5.6.7.8
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 步骤 4: 合并响应并返回给客户端                                               │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * 
 *   最终响应（合并 2 个答案）：
 *   
 *   Header:
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         ID = 1234                 |  必须与原请求 ID 匹配！
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |QR=1|OP=0|AA|TC|RD=1|RA|Z|RCODE=0  |  QR=1 表示响应
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         QDCOUNT = 2               |  2 个问题
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         ANCOUNT = 2               |  2 个答案
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   
 *   Question Section (不压缩):
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |    Question 1: abc.example.com    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |    Question 2: xyz.example.com    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   
 *   Answer Section (不压缩):
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |    Answer 1: abc.example.com      |
 *   |    TYPE=A, CLASS=IN, TTL=300      |
 *   |    RDLENGTH=4, RDATA=1.2.3.4      |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 *   |    Answer 2: xyz.example.com      |
 *   |    TYPE=A, CLASS=IN, TTL=300      |
 *   |    RDLENGTH=4, RDATA=5.6.7.8      |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+
 * 
 * ============================================================
 * 关键点总结
 * ============================================================
 * 
 * 1. 上游 DNS 只接受单个问题
 *    - 收到多个问题时，必须拆分成多个请求分别转发
 *    - 然后将所有响应合并成一个包返回
 * 
 * 2. ID 必须匹配
 *    - 返回给客户端的响应 ID 必须与原始请求相同
 *    - 转发给上游的请求可以使用相同 ID（简化实现）
 * 
 * 3. 压缩指针只在解析时处理
 *    - 解析请求时支持压缩指针
 *    - 生成响应时不使用压缩（简化实现）
 */
DNSAnswer forwardQuery(const sockaddr_in& resolverAddr, const DNSQuestion& question, uint16_t queryId)
{
    // 创建转发用的 socket
    int forwardSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (forwardSocket == -1)
    {
        perror("Failed to create forward socket");
        return DNSAnswer{};
    }
    
    // 构建转发请求（只包含 1 个问题）
    DNSMessage forwardRequest;
    forwardRequest.header.id = queryId;
    forwardRequest.header.flags = 0x0100;  // RD=1 (期望递归)
    forwardRequest.header.qdcount = 1;     // 关键：只有 1 个问题
    forwardRequest.header.ancount = 0;
    forwardRequest.header.nscount = 0;
    forwardRequest.header.arcount = 0;
    forwardRequest.questions.push_back(question);
    
    std::vector<uint8_t> requestBytes = forwardRequest.serialize();
    
    // 发送请求到上游 DNS 服务器
    if (sendto(forwardSocket, requestBytes.data(), requestBytes.size(), 0,
               reinterpret_cast<const struct sockaddr*>(&resolverAddr), sizeof(resolverAddr)) == -1)
    {
        perror("Failed to send to resolver");
        close(forwardSocket);
        return DNSAnswer{};
    }
    
    // 接收响应
    // recvfrom() 默认是阻塞调用
    char responseBuffer[512];
    socklen_t addrLen = sizeof(resolverAddr);
    int bytesReceived = recvfrom(forwardSocket, responseBuffer, sizeof(responseBuffer), 0,
                                  nullptr, nullptr);
    close(forwardSocket);
    
    if (bytesReceived == -1)
    {
        perror("Failed to receive from resolver");
        return DNSAnswer{};
    }
    
    // 解析响应
    const uint8_t* responseData = reinterpret_cast<uint8_t*>(responseBuffer);
    DNSHeader responseHeader = DNSHeader::parse(responseData);
    
    // 跳过 Header 和 Question 部分，解析 Answer
    size_t offset = 12;  // Header 大小
    
    // 跳过 Question 部分
    for (uint16_t i = 0; i < responseHeader.qdcount; i++)
    {
        DNSQuestion::parse(responseData, offset);
    }
    
    // 解析 Answer 部分
    DNSAnswer answer;
    if (responseHeader.ancount > 0)
    {
        answer = DNSAnswer::parse(responseData, offset);
    }
    
    return answer;
}

int main(int argc, char* argv[])
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
    
    // ==================== 1.5 解析命令行参数 ====================
    // 格式: ./your_server --resolver <ip>:<port>
    std::string resolverIp;
    int resolverPort = 0;
    
    for (int i = 1; i < argc; i++)
    {
        if (std::string(argv[i]) == "--resolver" && i + 1 < argc)
        {
            std::string resolverAddr = argv[i + 1];
            size_t colonPos = resolverAddr.find(':');
            if (colonPos != std::string::npos)
            {
                resolverIp = resolverAddr.substr(0, colonPos);
                resolverPort = std::stoi(resolverAddr.substr(colonPos + 1));
            }
            break;
        }
    }
    
    // 配置上游 DNS 服务器地址
    sockaddr_in resolverAddress{};
    if (!resolverIp.empty())
    {
        resolverAddress.sin_family = AF_INET;
        resolverAddress.sin_port = htons(resolverPort);
        inet_pton(AF_INET, resolverIp.c_str(), &resolverAddress.sin_addr);
        std::cout << "Using resolver: " << resolverIp << ":" << resolverPort << std::endl;
    }

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

        // ---------- 5.2 解析请求并构建 DNS 响应 ----------
        // 首先解析请求的 Header
        const uint8_t* requestData = reinterpret_cast<uint8_t*>(buffer);
        DNSHeader requestHeader = DNSHeader::parse(requestData);
        
        // 解析所有 Question（从 offset=12 开始，即 Header 之后）
        size_t offset = 12;  // DNS Header 固定 12 字节
        std::vector<DNSQuestion> requestQuestions;
        for (uint16_t i = 0; i < requestHeader.qdcount; i++)
        {
            DNSQuestion q = DNSQuestion::parse(requestData, offset);
            std::cout << "Query " << (i + 1) << " for domain: " << q.name << std::endl;
            requestQuestions.push_back(q);
        }
        
        // 使用 DNSMessage 统一管理响应
        DNSMessage response;
        
        // ===== 设置 Header =====
        // 从请求中复制 ID（必须匹配）
        response.header.id = requestHeader.id;
        
        // 从请求中提取需要复制的字段
        uint8_t requestOpcode = requestHeader.getOpcode();
        uint8_t requestRD = requestHeader.getRD();
        
        // 构建 flags 字段（16 bits）：
        // QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1) | RA(1) | Z(3) | RCODE(4)
        uint16_t qr = 1;                    // QR = 1 表示这是响应包
        uint16_t opcode = requestOpcode;    // OPCODE: 从请求复制
        uint16_t aa = 0;                    // AA = 0 非权威回答
        uint16_t tc = 0;                    // TC = 0 未截断
        uint16_t rd = requestRD;            // RD: 从请求复制
        uint16_t ra = 0;                    // RA = 0 不支持递归
        uint16_t z = 0;                     // Z = 0 保留字段
        // RCODE: 如果 OPCODE=0 则返回 0（无错误），否则返回 4（未实现）
        uint16_t rcode = (requestOpcode == 0) ? 0 : 4;
        
        // 按位组合 flags
        // |QR(1)|OPCODE(4)|AA(1)|TC(1)|RD(1)|RA(1)|Z(3)|RCODE(4)|
        response.header.flags = (qr << 15) | (opcode << 11) | (aa << 10) | 
                                (tc << 9) | (rd << 8) | (ra << 7) | 
                                (z << 4) | rcode;
        
        response.header.qdcount = requestQuestions.size();  // 问题数：与请求相同
        response.header.ancount = requestQuestions.size();  // 回答数：每个问题一个回答
        response.header.nscount = 0;    // 授权记录数：0
        response.header.arcount = 0;    // 附加记录数：0
        
        // ===== 为每个 Question 添加 Question 和 Answer =====
        for (const auto& reqQuestion : requestQuestions)
        {
            // 添加 Question（从请求中复制，不压缩）
            DNSQuestion question;
            question.name = reqQuestion.name;
            question.type = 1;       // TYPE = 1 (A 记录)
            question.qclass = 1;     // CLASS = 1 (IN，互联网)
            response.questions.push_back(question);
            
            // 如果配置了 resolver，转发查询；否则返回固定 IP
            if (!resolverIp.empty())
            {
                // 转发查询到上游 DNS 服务器
                // 注意：上游服务器只接受单个问题，所以每个问题单独转发
                DNSAnswer answer = forwardQuery(resolverAddress, reqQuestion, requestHeader.id);
                response.answers.push_back(answer);
            }
            else
            {
                // 没有配置 resolver，返回固定 IP（兼容之前的阶段）
                DNSAnswer answer;
                answer.name = reqQuestion.name;
                answer.type = 1;         // TYPE = 1 (A 记录)
                answer.aclass = 1;       // CLASS = 1 (IN，互联网)
                answer.ttl = 60;         // TTL = 60 秒
                answer.rdlength = 4;     // RDATA 长度 = 4 字节（IPv4 地址）
                answer.rdata = {8, 8, 8, 8};  // IP 地址 8.8.8.8
                response.answers.push_back(answer);
            }
        }
        
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
