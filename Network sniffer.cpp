#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <npcap/npcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Ws2_32.lib")

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    ether_header* eth_hdr = (ether_header*)pkt_data;

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        iphdr* ip_hdr = (iphdr*)(pkt_data + sizeof(ether_header));

        char src_ip[16], dst_ip[16];
        inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip_hdr->daddr), dst_ip, sizeof(dst_ip));

        std::cout << "IP Packet: " << src_ip << " -> " << dst_ip << " Protocol: ";

        switch (ip_hdr->protocol) {
        case IPPROTO_TCP: {
            tcphdr* tcp_hdr = (tcphdr*)(pkt_data + sizeof(ether_header) + sizeof(iphdr));
            std::cout << "TCP Ports: " << ntohs(tcp_hdr->th_sport) << " -> " << ntohs(tcp_hdr->th_dport);
            break;
        }
        case IPPROTO_UDP: {
            udphdr* udp_hdr = (udphdr*)(pkt_data + sizeof(ether_header) + sizeof(iphdr));
            std::cout << "UDP Ports: " << ntohs(udp_hdr->uh_sport) << " -> " << ntohs(udp_hdr->uh_dport);
            break;
        }
        case IPPROTO_ICMP:
            std::cout << "ICMP";
            break;
        default:
            std::cout << "Other";
        }
        std::cout << std::endl;
    }
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        std::cout << "ARP packet detected" << std::endl;
    }
}

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* fp;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    int i = 0;
    for (d = alldevs; d != NULL; d = d->next) {
        std::cout << ++i << ". " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")" << std::endl;
        else
            std::cout << " (No description available)" << std::endl;
    }

    if (i == 0) {
        std::cerr << "No interfaces found!" << std::endl;
        return 1;
    }

    std::cout << "Enter the interface number (1-" << i << "): ";
    int inum;
    std::cin >> inum;

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    if ((fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        std::cerr << "Error opening adapter: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    struct bpf_program fcode;
    if (pcap_compile(fp, &fcode, "tcp", 1, 0xFFFFFF00) < 0) {
        std::cerr << "Error compiling filter" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_setfilter(fp, &fcode) < 0) {
        std::cerr << "Error setting filter" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_loop(fp, 0, packet_handler, NULL);

    pcap_freealldevs(alldevs);
    return 0;
}
