#include "flow.hpp"
#include <mutex>
#include <map>
#include <iostream>

static std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flow_map;
std::mutex g_connections_mutex;

constexpr size_t MAX_CONNECTIONS = 10000;
constexpr double PKT_RATE_THRESHOLD = 100.0;
constexpr double BYTE_RATE_THRESHOLD = 1e6;

bool updateFlow(const FlowKey& key, size_t packet_size, const std::string& proto) {
    std::lock_guard<std::mutex> lock(flow_mutex);

    auto& stat = flow_map[key];
    auto now = std::chrono::steady_clock::now();

    if (stat.packets == 0) {
        stat.first_seen = now;
        stat.protocol = proto;
    }
    stat.packets++;
    stat.bytes += packet_size;
    stat.last_seen = now;

    auto duration = std::chrono::duration_cast<std::chrono::seconds>(stat.last_seen - stat.first_seen).count();
    if (duration > 0 && !stat.flagged_anomaly) {
        double pkt_rate = stat.packets / static_cast<double>(duration);
        double byte_rate = stat.bytes / static_cast<double>(duration);

        if (pkt_rate > PKT_RATE_THRESHOLD || byte_rate > BYTE_RATE_THRESHOLD) {
            stat.flagged_anomaly = true;
            std::cerr << "[!] Anomaly Detected in flow\n";
            return true;
        }
    }

    // Limit memory usage
    if (flow_map.size() > MAX_CONNECTIONS) {
        auto oldest = flow_map.begin();
        for (auto it = flow_map.begin(); it != flow_map.end(); ++it) {
            if (it->second.last_seen < oldest->second.last_seen) {
                oldest = it;
            }
        }
        flow_map.erase(oldest);
    }

    return false;
}
