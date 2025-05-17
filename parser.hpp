#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

/** All packet header structs are packed to avoid padding. */
#pragma pack(push,1)
struct EthernetHeader { uint8_t dst[6], src[6]; uint16_t type; };
struct IPv4Header     { uint8_t ver_ihl, tos; uint16_t len, id, flags_off; uint8_t ttl, proto; uint16_t checksum; uint32_t src, dst; };
struct IPv6Header     { uint32_t vcf; uint16_t payload_len; uint8_t next_header, hop_limit; uint8_t src[16], dst[16]; };
struct TCPHeader      { uint16_t sport, dport; uint32_t seq, ack; uint8_t data_off, flags; uint16_t win, checksum, urg; };
struct UDPHeader      { uint16_t sport, dport, len, checksum; };
struct ICMPHeader     { uint8_t type, code; uint16_t checksum; uint32_t rest; };
#pragma pack(pop)

/**
 * Parse functions return the header length (offset) or zero on failure.
 */
size_t parse_ethernet(const u_char* pkt, size_t caplen, EthernetHeader& eth);
size_t parse_ipv4    (const u_char* pkt, size_t caplen, IPv4Header& ip);
size_t parse_tcp     (const u_char* pkt, size_t caplen, TCPHeader& tcp);
size_t parse_udp     (const u_char* pkt, size_t caplen, UDPHeader& udp);
size_t parse_icmp    (const u_char* pkt, size_t caplen, ICMPHeader& icmp);

/**
 * Utility converters and dumps.
 */
std::string ipv4_to_string(uint32_t ip);
std::string ipv6_to_string(const uint8_t ip6[16]);
std::string hex_dump(const u_char* data, size_t len, size_t max_bytes = 64);
std::string ascii_dump(const u_char* data, size_t len, size_t max_bytes = 64);
