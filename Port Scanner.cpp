#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Iphlpapi.lib")

std::mutex cout_mutex;
std::atomic<int> threads_completed(0);

struct ScanParams {
    std::string target;
    unsigned short start_port;
    unsigned short end_port;
    int scan_type;
    int timeout_ms;
    int max_threads;
};

bool is_host_alive(const std::string& target) {
    HANDLE hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    IPAddr ip_addr;
    InetPtonA(AF_INET, target.c_str(), &ip_addr);

    char send_data[32] = "Echo Request";
    char reply_buffer[sizeof(ICMP_ECHO_REPLY) + 32];
    DWORD reply_size = sizeof(reply_buffer);

    DWORD result = IcmpSendEcho(hIcmpFile, ip_addr, send_data, 32,
        NULL, reply_buffer, reply_size, 1000);

    IcmpCloseHandle(hIcmpFile);
    return result > 0;
}

bool tcp_connect_scan(const std::string& target, unsigned short port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    sockaddr_in service;
    service.sin_family = AF_INET;
    InetPtonA(AF_INET, target.c_str(), &service.sin_addr);
    service.sin_port = htons(port);

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    connect(sock, (SOCKADDR*)&service, sizeof(service));

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);

    timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    int result = select(0, NULL, &writefds, NULL, &timeout);
    if (result <= 0) {
        closesocket(sock);
        return false;
    }

    int error = 0;
    int error_len = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &error_len);

    closesocket(sock);
    return error == 0;
}

bool udp_scan(const std::string& target, unsigned short port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    sockaddr_in service;
    service.sin_family = AF_INET;
    InetPtonA(AF_INET, target.c_str(), &service.sin_addr);
    service.sin_port = htons(port);

    const char* buf = "";
    int sent = sendto(sock, buf, 0, 0, (SOCKADDR*)&service, sizeof(service));
    if (sent == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    int result = select(0, &readfds, NULL, NULL, &timeout);
    if (result <= 0) {
        closesocket(sock);
        return true;
    }

    char recv_buf[256];
    sockaddr_in from;
    int from_len = sizeof(from);
    recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (SOCKADDR*)&from, &from_len);

    closesocket(sock);
    return true;
}

void scan_ports_range(const ScanParams& params, unsigned short start, unsigned short end) {
    for (unsigned short port = start; port <= end; ++port) {
        bool is_open = false;

        switch (params.scan_type) {
        case 1:
            is_open = tcp_connect_scan(params.target, port, params.timeout_ms);
            break;
        case 2:
            is_open = udp_scan(params.target, port, params.timeout_ms);
            break;
        default:
            is_open = tcp_connect_scan(params.target, port, params.timeout_ms);
            break;
        }

        if (is_open) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Port " << port << " is open" << std::endl;
        }
    }

    threads_completed++;
}

void start_scan(const ScanParams& params) {
    if (!is_host_alive(params.target)) {
        std::cerr << "Host is not reachable or does not respond to ICMP." << std::endl;
        return;
    }

    std::cout << "Starting scan for " << params.target << " (ports "
        << params.start_port << "-" << params.end_port << ")" << std::endl;

    int total_ports = params.end_port - params.start_port + 1;
    int ports_per_thread = total_ports / params.max_threads;
    int remaining_ports = total_ports % params.max_threads;

    std::vector<std::thread> threads;

    unsigned short current_start = params.start_port;
    for (int i = 0; i < params.max_threads; ++i) {
        unsigned short current_end = current_start + ports_per_thread - 1;
        if (i < remaining_ports) {
            current_end++;
        }

        if (current_end > params.end_port) {
            current_end = params.end_port;
        }

        threads.emplace_back(scan_ports_range, params, current_start, current_end);
        current_start = current_end + 1;
    }

    for (auto& thread : threads) {
        thread.join();
    }

    std::cout << "Scan completed." << std::endl;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    ScanParams params;

    std::cout << "Enter target IP or hostname: ";
    std::cin >> params.target;

    addrinfo hints = {};
    hints.ai_family = AF_INET;
    addrinfo* result = nullptr;

    if (getaddrinfo(params.target.c_str(), nullptr, &hints, &result) != 0) {
        std::cerr << "Failed to resolve hostname." << std::endl;
        WSACleanup();
        return 1;
    }

    char ip_str[INET_ADDRSTRLEN];
    InetNtopA(AF_INET, &((sockaddr_in*)result->ai_addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
    params.target = ip_str;
    freeaddrinfo(result);

    std::cout << "Enter start port: ";
    std::cin >> params.start_port;

    std::cout << "Enter end port: ";
    std::cin >> params.end_port;

    std::cout << "Select scan type (1 - TCP Connect, 2 - UDP Scan): ";
    std::cin >> params.scan_type;

    std::cout << "Enter timeout in milliseconds: ";
    std::cin >> params.timeout_ms;

    std::cout << "Enter max threads: ";
    std::cin >> params.max_threads;

    if (params.start_port > params.end_port ||
        params.start_port < 1 || params.end_port > 65535 ||
        params.scan_type < 1 || params.scan_type > 2 ||
        params.timeout_ms <= 0 || params.max_threads <= 0) {
        std::cerr << "Invalid input parameters." << std::endl;
        WSACleanup();
        return 1;
    }

    start_scan(params);

    WSACleanup();
    return 0;
}
