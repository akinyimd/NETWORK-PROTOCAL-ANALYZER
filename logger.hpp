#pragma once
#include <string>
#include <atomic>

// Initialize logging. Call once at start.
void init_logger(bool verbose,
                 bool dump_payload,
                 const std::string& file_path = "");

// Thread-safe logging call; includes timestamp.
void log_msg(const std::string& msg);

// Shutdown logger (flush, close file if used).
void shutdown_logger();
