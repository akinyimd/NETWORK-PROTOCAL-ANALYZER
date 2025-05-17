#include <iostream>
#include <fstream>
#include <mutex>
#include <chrono>
#include <ctime>
#include <iomanip>
#include "capture.hpp"  // for MAX_PACKET_DUMP_SIZE if needed
#include <stdexcept>

/**
 * Provided flags and globals:
 *   extern bool g_verbose, g_dump_payload, g_log_to_file;
 *   extern std::ofstream g_log_file;
 *   extern std::mutex g_log_mutex;
 */

extern bool g_verbose;
extern bool g_dump_payload;
extern bool g_log_to_file;
extern std::ofstream g_log_file;
extern std::mutex g_log_mutex;

/** Get current time stamp [HH:MM:SS]. */
static std::string timeStamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    char buf[20]; tm tm_; localtime_s(&tm_, &t);
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm_);
    return buf;
}

/**
 * Thread-safe logging. Always prints; optionally logs to file.
 */
void log_msg(const std::string& msg) {
    std::lock_guard lk(g_log_mutex);
    std::string line = "[" + timeStamp() + "] " + msg + "\n";
    std::cout << line;
    if (g_log_to_file) {
        if (!g_log_file.is_open())
            throw std::runtime_error("Log file not open");
        g_log_file << line << std::flush;
    }
}
