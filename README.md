# 🛡️ Network Protocol Analyzer (C++)

A robust and modular **C++ network analyzer** that captures live network traffic, parses packet headers, tracks protocol flows, detects anomalies, and classifies common protocols like HTTP, DNS, SSH, FTP, and more.

---

## 🚀 Features

✅ Live packet capturing using **Npcap/libpcap**  

✅ Parses **IPv4**, **IPv6**, **TCP**, **UDP**, **ICMP**, **ARP**  

✅ Detects protocols based on **payload signatures** (HTTP, FTP, SSH, DNS...)  

✅ Tracks **flow statistics** (bytes, packets, rate)  

✅ Flags **anomalies** based on traffic thresholds  

✅ Optional **hex/ASCII payload dumps**  

✅ Modular architecture for easy maintenance and scalability  

✅ Supports **BPF filters**, **verbose mode**, and **log-to-file**

---

## 🧠 Architecture

This project is cleanly separated into modules for better organization:

📁 network-analyzer/
│
├── main.cpp ▶️ Entry point and CLI
├── flow.hpp/.cpp 📊 Flow tracking & anomaly detection
├── capture.hpp/.cpp 📡 Packet capture and interface selection
├── parser.hpp/.cpp 📦 Packet parsing & protocol detection
├── logger.hpp/.cpp 🪵 Thread-safe logging
├── README.md 📘 You're here!

---

## ⚙️ How to Compile

### 🪟 On Windows (Npcap SDK installed)

```bash
g++ main.cpp flow.cpp capture.cpp parser.cpp logger.cpp -I"C:\Users\user 1\Downloads\npcap-sdk-1.15.zip\Include" -L"C:\Users\user 1\Downloads\npcap-sdk-1.15.zip\Lib" -lwpcap -o analyzer.exe

🐧 On Linux (libpcap)

g++ main.cpp flow.cpp capture.cpp parser.cpp logger.cpp -lpcap -o analyzer


🛠️ Usage

./analyzer [options]

Option	Description
-i <iface>	Network interface to listen on
-f "<bpf>"	BPF capture filter (e.g., "port 80")
-p <pattern>	Match pattern in payloads
-v	Enable verbose mode
-d	Dump payloads in ASCII + HEX
-l <file>	Log output to specified file
-h	Show help message

🧪 Example
bash
Copy
Edit
./analyzer -i eth0 -f "port 80" -p "password" -v -d -l traffic_log.txt
📊 Sample Output
makefile
Copy
Edit
[12:00:03] IPv4: 192.168.0.5:443 -> 192.168.0.25:50234 | TCP [PA] [HTTP]
Payload: 98 bytes
ASCII: GET /login.html HTTP/1.1\r\nHost: site.com\r\n\r\n
HEX: 47 45 54 20 2F 6C 6F 67 69 6E ...
📌 Requirements
C++17 or higher

Windows: Npcap SDK

Linux: libpcap (sudo apt install libpcap-dev)

g++ or MSVC

👨‍💻 Author
AKINYIMD

📝 License
This project is licensed under the MIT License. You’re free to use, modify, and distribute it.


