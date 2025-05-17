// main.cpp
#include "capture.hpp"
#include "parser.hpp"
#include "flow.hpp"
#include "logger.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <csignal>

// Globals from modules
extern bool g_verbose;
extern bool g_dump_payload;
extern bool g_log_to_file;
extern std::string g_pattern_filter;
extern std::mutex g_log_mutex;
extern std::ofstream g_log_file;
static std::atomic<bool> g_running{true};

// Signal handler for clean shutdown
static void handle_signal(int) {
    g_running = false;
}

// Print CLI help
static void print_help(const char* prog) {
    std::cout
        << "Enhanced Network Protocol Analyzer\n"
        << "Usage: " << prog << " [options]\n"
        << "Options:\n"
        << "  -i <iface>    Network interface to capture from\n"
        << "  -f <bpf>      BPF filter expression\n"
        << "  -p <pattern>  Payload pattern (case-insensitive)\n"
        << "  -v            Verbose mode\n"
        << "  -d            Dump packet payloads (hex+ASCII)\n"
        << "  -l <file>     Log to file\n"
        << "  -h            Display this help and exit\n"
        << std::endl;
}

int main(int argc, char* argv[]) {
    std::string iface, bpf_filter, log_path;
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i+1 < argc) {
            iface = argv[++i];
        } else if (arg == "-f" && i+1 < argc) {
            bpf_filter = argv[++i];
        } else if (arg == "-p" && i+1 < argc) {
            g_pattern_filter = argv[++i];
        } else if (arg == "-v") {
            g_verbose = true;
        } else if (arg == "-d") {
            g_dump_payload = true;
        } else if (arg == "-l" && i+1 < argc) {
            g_log_to_file = true;
            log_path = argv[++i];
        } else if (arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_help(argv[0]);
            return 1;
        }
    }

    // If no interface, list and prompt
    if (iface.empty()) {
        list_interfaces();
        std::cout << "Select interface number: ";
        int choice; std::cin >> choice;
        pcap_if_t* devs = nullptr;
        char err[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&devs, err) == -1 || !devs) {
            std::cerr << "Error listing interfaces: " << err << "\n";
            return 1;
        }
        for (int i = 1; devs && i < choice; devs = devs->next, ++i);
        if (!devs) {
            std::cerr << "Invalid interface choice\n";
            pcap_freealldevs(devs);
            return 1;
        }
        iface = devs->name;
        pcap_freealldevs(devs);
    }

    // Initialize logging
    if (g_log_to_file) {
        g_log_file.open(log_path, std::ios::app);
        if (!g_log_file) {
            std::cerr << "Failed to open log file: " << log_path << "\n";
            return 1;
        }
    }

    // Install signal handler
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        // Open capture
        auto handle = open_capture(iface, /*offline=*/false, bpf_filter);
        log_msg("Starting capture on " + iface +
                (bpf_filter.empty() ? "" : " with filter: " + bpf_filter));

        // Stats thread: every 10s display top flows
        std::thread stats_thread([&](){
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                display_flows(/*top_n=*/10);
            }
        });

        // Start capture loop
        start_capture(handle,
            [](u_char*, const pcap_pkthdr* hdr, const u_char* pkt){
                // Delegate to our packet handler in parser/flow modules
                packet_handler(hdr, pkt);  
                // Stop if signaled
                if (!g_running) pcap_breakloop((pcap_t*)nullptr);
            });

        // Clean up
        g_running = false;
        if (stats_thread.joinable()) stats_thread.join();
        pcap_close(handle);
        if (g_log_to_file) g_log_file.close();
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
