#include "capture.hpp"

pcap_t* open_capture(const std::string& dev, bool offline, const std::string& filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;

    if (offline) {
        handle = pcap_open_offline(dev.c_str(), errbuf);
    } else {
        // promiscuous mode, 1s timeout
        handle = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
    }
    if (!handle) {
        throw std::runtime_error(std::string("pcap_open failed: ") + errbuf);
    }

    if (!filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(handle, &fp) == -1) {
            std::string e = pcap_geterr(handle);
            pcap_freecode(&fp);
            throw std::runtime_error("BPF filter error: " + e);
        }
        pcap_freecode(&fp);
    }

    return handle;
}

void start_capture(pcap_t* handle, pcap_handler callback, u_char* user_data) {
    int ret = pcap_loop(handle, 0, callback, user_data);
    if (ret == PCAP_ERROR) {
        throw std::runtime_error(std::string("pcap_loop error: ") + pcap_geterr(handle));
    }
}
