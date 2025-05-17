#include "parser.hpp"
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstring>

size_t parse_ethernet(const u_char* pkt, size_t caplen, EthernetHeader& eth) {
    if (caplen < sizeof(EthernetHeader)) return 0;
    std::memcpy(&eth, pkt, sizeof(eth));
    return sizeof(eth);
}

size_t parse_ipv4(const u_char* pkt, size_t caplen, IPv4Header& ip) {
    if (caplen < sizeof(IPv4Header)) return 0;
    std::memcpy(&ip, pkt, sizeof(ip));
    size_t ihl = (ip.ver_ihl & 0x0F) * 4;
    if (ihl < 20 || caplen < ihl) return 0;
    return ihl;
}

size_t parse_tcp(const u_char* pkt, size_t caplen, TCPHeader& tcp) {
    if (caplen < sizeof(TCPHeader)) return 0;
    std::memcpy(&tcp, pkt, sizeof(tcp));
    size_t thl = ((tcp.data_off >> 4) & 0x0F) * 4;
    if (thl < 20 || caplen < thl) return 0;
    return thl;
}

size_t parse_udp(const u_char* pkt, size_t caplen, UDPHeader& udp) {
    if (caplen < sizeof(UDPHeader)) return 0;
    std::memcpy(&udp, pkt, sizeof(udp));
    return sizeof(udp);
}

size_t parse_icmp(const u_char* pkt, size_t caplen, ICMPHeader& icmp) {
    if (caplen < sizeof(ICMPHeader)) return 0;
    std::memcpy(&icmp, pkt, sizeof(icmp));
    return sizeof(icmp);
}

std::string ipv4_to_string(uint32_t ip) {
    struct in_addr a; a.s_addr = ip;
    return inet_ntoa(a);
}

std::string ipv6_to_string(const uint8_t ip6[16]) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip6, buf, sizeof(buf));
    return buf;
}

std::string hex_dump(const u_char* data, size_t len, size_t max_bytes) {
    std::ostringstream ss;
    size_t disp = std::min(len, max_bytes);
    for (size_t i = 0; i < disp; ++i) {
        if (i % 16 == 0) ss << std::setw(4) << std::setfill('0') << std::hex << i << "  ";
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)data[i] << " ";
        if (i % 16 == 15) ss << "\n";
    }
    if (len > disp) ss << "\n... (" << (len - disp) << " more bytes)\n";
    return ss.str();
}

std::string ascii_dump(const u_char* data, size_t len, size_t max_bytes) {
    std::ostringstream ss;
    size_t disp = std::min(len, max_bytes);
    for (size_t i = 0; i < disp; ++i) {
        ss << (std::isprint(data[i]) ? (char)data[i] : '.');
    }
    if (len > disp) ss << "...";
    return ss.str();
}
