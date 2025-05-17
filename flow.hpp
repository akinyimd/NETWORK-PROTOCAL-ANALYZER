#ifndef FLOW_HPP
#define FLOW_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <chrono>

struct FlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t proto;

    bool operator==(const FlowKey& o) const {
        return src_ip == o.src_ip &&
               dst_ip == o.dst_ip &&
               src_port == o.src_port &&
               dst_port == o.dst_port &&
               proto == o.proto;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const {
        return std::hash<uint32_t>()(k.src_ip) ^
               std::hash<uint32_t>()(k.dst_ip) ^
               std::hash<uint16_t>()(k.src_port) ^
               std::hash<uint16_t>()(k.dst_port) ^
               std::hash<uint8_t>()(k.proto);
    }
};

struct FlowStats {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    std::string protocol;
    bool flagged_anomaly = false;
};

bool updateFlow(const FlowKey& key, size_t packet_size, const std::string& proto);

#endif // FLOW_HPP
