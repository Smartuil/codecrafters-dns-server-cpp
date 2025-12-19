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
        std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;

        // ---------- 5.2 构建 DNS 响应 ----------
        // TODO: 这里需要实现真正的 DNS 响应逻辑
        // 目前只返回一个空字节，这不是有效的 DNS 响应
        // 
        // 完整的 DNS 响应应包含：
        //   - Header（12 字节）：包含 ID、标志、各部分计数
        //   - Question Section：原样复制查询中的问题
        //   - Answer Section：包含查询结果（IP 地址等）
        char response[1] = { '\0' };

        // ---------- 5.3 发送 DNS 响应 ----------
        // sendto() 向指定地址发送 UDP 数据
        // 参数说明：
        //   - udpSocket: 发送数据的 socket
        //   - response: 要发送的数据
        //   - sizeof(response): 数据长度
        //   - 0: 标志位
        //   - clientAddress: 目标地址（即发送查询的客户端）
        //   - sizeof(clientAddress): 地址结构体大小
        if (sendto(udpSocket, response, sizeof(response), 0, 
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
