#pragma once
#include <string>
#include <pcap.h>
#include <stdexcept>

/**
 * Opens a live network interface or offline pcap file.
 * @param device_or_file  Interface name (e.g. "eth0") or file path.
 * @param offline         true = open as pcap file; false = live capture.
 * @param bpf_filter      BPF filter expression (empty = no filter).
 * @return                pcap_t* handle on success.
 * @throws std::runtime_error on failure.
 */
pcap_t* open_capture(const std::string& device_or_file,
                     bool offline,
                     const std::string& bpf_filter = "");

/**
 * Starts the capture loop. Blocks until break or error.
 * @param handle    pcap handle from open_capture().
 * @param callback  The pcap_handler callback to invoke per packet.
 * @param user_data Optional user data passed to callback.
 * @throws std::runtime_error on error.
 */
void start_capture(pcap_t* handle,
                   pcap_handler callback,
                   u_char* user_data = nullptr);
