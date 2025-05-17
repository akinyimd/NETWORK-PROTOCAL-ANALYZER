#define _WIN32_WINNT 0x0600
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <csignal>
#include <cctype>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
#endif

//–– Constants & Globals –––––––––––––––––––––––––––––––––––––––––––––

static const size_t ETHERNET_HEADER_LEN   = 14;
static const size_t MAX_PACKET_DUMP_SIZE  = 64;
static const size_t MAX_CONNECTIONS      = 10000;
static const double PACKET_RATE_THRESHOLD = 100.0;   // pkts/sec
static const double BYTE_RATE_THRESHOLD   = 1e6;     // bytes/sec

std::atomic<bool> g_running{true};
bool g_verbose       = false;
bool g_dump_payload  = false;
bool g_log_to_file   = false;
std::string g_pattern_filter;
std::ofstream g_log_file;
std::mutex g_log_mutex;

// Known protocol names
const std::map<uint8_t,std::string> PROTOCOLS = {
    {1,"ICMP"},{6,"TCP"},{17,"UDP"},{2,"IGMP"},
    {89,"OSPF"},{47,"GRE"},{50,"ESP"},{51,"AH"},
    {58,"ICMPv6"},{132,"SCTP"}
};

// Patterns for detection
const std::vector<std::pair<std::string,std::string>> PATTERNS = {
    {"http","HTTP"},{"GET ","HTTP"},{"POST ","HTTP"},{"HTTP/1.","HTTP"},
    {"ssh-","SSH"},{"220 ","FTP"},{"user ","FTP"},{"pass ","FTP"},
    {"ehlo","SMTP"},{"helo","SMTP"},{"mail from","SMTP"},{"rcpt to","SMTP"},
    {"\x13bittorrent protocol","BitTorrent"},{"dns","DNS"},{"dhcp","DHCP"}
};

//–– Packet Header Structs –––––––––––––––––––––––––––––––––––––––––––

#pragma pack(push,1)
struct EthernetHeader { uint8_t dst[6],src[6]; uint16_t type; };
struct IPv4Header     { uint8_t ver_ihl,tos; uint16_t len,id,flags_off; uint8_t ttl,proto; uint16_t checksum; uint32_t src,dst; };
struct IPv6Header     { uint32_t vcf; uint16_t payload_len; uint8_t next_header, hop_limit; uint8_t src[16], dst[16]; };
struct TCPHeader      { uint16_t sport,dport; uint32_t seq,ack; uint8_t data_off,flags; uint16_t win,checksum,urg; };
struct UDPHeader      { uint16_t sport,dport,len,checksum; };
struct ICMPHeader     { uint8_t type,code; uint16_t checksum; uint32_t rest; };
#pragma pack(pop)

//–– Flow Tracking Types –––––––––––––––––––––––––––––––––––––––––––––

struct FlowKey {
    uint32_t src_ip,dst_ip;
    uint16_t src_port,dst_port;
    uint8_t  proto;
    bool operator==(FlowKey const& o) const = default;
};

struct FlowKeyHash {
    size_t operator()(FlowKey const& k) const noexcept {
        uint64_t v = (uint64_t)k.src_ip<<32 ^ (uint64_t)k.dst_ip<<16
                   ^ (uint64_t)k.src_port<<8 ^ (uint64_t)k.dst_port
                   ^ k.proto;
        return std::hash<uint64_t>()(v);
    }
};

struct FlowStats {
    uint64_t packets=0, bytes=0;
    std::chrono::steady_clock::time_point first,last;
    bool anomaly=false;
};

// Global flows map
std::unordered_map<FlowKey,FlowStats,FlowKeyHash> g_flows;
std::mutex g_flows_mutex;

//–– Utility Functions –––––––––––––––––––––––––––––––––––––––––––––––

std::string timeStamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    char buf[20]; tm tm_; localtime_s(&tm_,&t);
    strftime(buf,sizeof(buf),"%H:%M:%S",&tm_);
    return buf;
}

void log_msg(const std::string& m) {
    std::lock_guard lk(g_log_mutex);
    std::string line = "[" + timeStamp() + "] " + m + "\n";
    std::cout << line;
    if(g_log_to_file) g_log_file << line << std::flush;
}

std::string ip4ToString(uint32_t ip) {
    struct in_addr a{ ip };
    return inet_ntoa(a);
}

std::string ip6ToString(const uint8_t ip6[16]) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip6, buf, sizeof(buf));
    return buf;
}

std::string hexDump(const u_char* data, size_t len) {
    std::ostringstream ss; size_t lim = std::min(len,MAX_PACKET_DUMP_SIZE);
    for(size_t i=0;i<lim;++i){
        if(i%16==0) ss<<std::setw(4)<<std::setfill('0')<<std::hex<<i<<"  ";
        ss<<std::setw(2)<<std::setfill('0')<<std::hex<<(int)data[i]<<" ";
        if(i%16==15) ss<<"\n";
    }
    if(len>lim) ss<<"...+"<<(len-lim)<<" bytes\n";
    return ss.str();
}

std::string asciiDump(const u_char* data, size_t len) {
    std::ostringstream ss; size_t lim = std::min(len,MAX_PACKET_DUMP_SIZE);
    for(size_t i=0;i<lim;++i) ss<<(isprint(data[i])?(char)data[i]:'.');
    if(len>lim) ss<<"...";
    return ss.str();
}

bool containsPattern(const u_char* data, size_t len, std::string& outProt) {
    outProt.clear();
    std::string lower((char*)data, (char*)data+std::min(len,MAX_PACKET_DUMP_SIZE));
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for(auto& pr: PATTERNS) {
        if(lower.find(pr.first) != std::string::npos) {
            if(!outProt.empty()) outProt += ",";
            outProt += pr.second;
        }
    }
    return !outProt.empty();
}

//–– Flow Stats –––––––––––––––––––––––––––––––––––––––––––––––––––––

bool update_flow(const FlowKey& k, size_t pkt_len) {
    using clk = std::chrono::steady_clock;
    auto now = clk::now();
    std::lock_guard lk(g_flows_mutex);
    auto& s = g_flows[k];
    if(s.packets==0) s.first = now;
    s.last = now;
    s.packets++; s.bytes += pkt_len;
    double secs = std::chrono::duration<double>(s.last - s.first).count();
    if(secs>0.1) {
        double pps = s.packets/secs, bps = s.bytes/secs;
        if(!s.anomaly && (pps>PACKET_RATE_THRESHOLD||bps>BYTE_RATE_THRESHOLD)) {
            s.anomaly = true; return true;
        }
    }
    // prune
    if(g_flows.size()>MAX_CONNECTIONS) {
        auto oldest = g_flows.begin();
        for(auto it=g_flows.begin();it!=g_flows.end();++it)
            if(it->second.last < oldest->second.last) oldest = it;
        g_flows.erase(oldest);
    }
    return false;
}

void display_flows(size_t top_n=10) {
    std::vector<std::pair<FlowKey,FlowStats>> v;
    { std::lock_guard lk(g_flows_mutex);
      v.assign(g_flows.begin(), g_flows.end()); }
    std::sort(v.begin(),v.end(),
        [](auto const&a,auto const&b){ return a.second.bytes>b.second.bytes; });
    log_msg("---- Top Flows ----");
    for(size_t i=0;i<v.size()&&i<top_n;++i){
        auto& [k,s]=v[i];
        std::ostringstream os;
        os<<ip4ToString(k.src_ip)<<":"<<k.src_port<<"->"
          <<ip4ToString(k.dst_ip)<<":"<<k.dst_port
          <<" pkts="<<s.packets<<" bytes="<<s.bytes
          <<(s.anomaly?" [ANOMALY]":"");
        log_msg(os.str());
    }
}

//–– Interface Listing ––––––––––––––––––––––––––––––––––––––––––––––

void list_interfaces() {
    char err[PCAP_ERRBUF_SIZE]; pcap_if_t* devs;
    if(pcap_findalldevs(&devs,err)==-1){ std::cerr<<err<<"\n"; return; }
    int idx=0;
    for(auto d=devs;d;d=d->next) {
        std::cout<< ++idx <<". "<<(d->description?d->description:d->name)
                 <<" ("<<d->name<<")\n";
    }
    pcap_freealldevs(devs);
}

//–– Packet Handler ––––––––––––––––––––––––––––––––––––––––––––––––––

void packet_handler(u_char* user, const pcap_pkthdr* h, const u_char* pkt) {
    if(!g_running) return;
    size_t caplen=h->caplen; if(caplen<ETHERNET_HEADER_LEN) return;
    auto eth = (EthernetHeader*)pkt;
    uint16_t type=ntohs(eth->type);
    size_t offset=ETHERNET_HEADER_LEN, rem=caplen-offset;
    std::ostringstream os; FlowKey key{};
    // IPv4
    if(type==0x0800 && rem>=20) {
        auto ip = (IPv4Header*)(pkt+offset);
        size_t ihl=(ip->ver_ihl&0x0F)*4; if(ihl<20||rem<ihl) return;
        key={ip->src,ip->dst,0,0,ip->proto};
        os<<"IPv4 "<<ip4ToString(ip->src)<<"->"<<ip4ToString(ip->dst);
        offset+=ihl; rem-=ihl;
    }
    // IPv6
    else if(type==0x86DD && rem>=40) {
        auto ip6 = (IPv6Header*)(pkt+offset);
        key={0,0,0,0,ip6->next_header};
        os<<"IPv6 "<<ip6ToString(ip6->src)<<"->"<<ip6ToString(ip6->dst);
        offset+=40; rem-=40;
    }
    // ARP
    else if(type==0x0806) {
        log_msg("ARP packet");
        return;
    } else return;

    // Transport
    std::string proto_name = PROTOCOLS.count(key.proto)?PROTOCOLS.at(key.proto):"PROT"+std::to_string(key.proto);
    os<<" "<<proto_name;
    // TCP
    if(key.proto==6 && rem>=20) {
        auto tcp=(TCPHeader*)(pkt+offset);
        size_t thl=((tcp->data_off>>4)&0x0F)*4; if(thl<20||rem<thl) return;
        key.src_port=ntohs(tcp->sport); key.dst_port=ntohs(tcp->dport);
        os<<" "<<key.src_port<<"->"<<key.dst_port;
        offset+=thl; rem-=thl;
    }
    // UDP
    else if(key.proto==17 && rem>=8) {
        auto udp=(UDPHeader*)(pkt+offset);
        key.src_port=ntohs(udp->sport); key.dst_port=ntohs(udp->dport);
        os<<" "<<key.src_port<<"->"<<key.dst_port;
        offset+=8; rem-=8;
    }
    // ICMP
    else if(key.proto==1 && rem>=4) {
        auto ic=(ICMPHeader*)(pkt+offset);
        os<<" ICMP "<<int(ic->type);
    }

    // Pattern detection
    std::string detected;
    if(!g_pattern_filter.empty()) {
        // user filter vs pattern detection
    }
    containsPattern(pkt+offset,rem,detected);
    if(!detected.empty()) os<<" ["<<detected<<"]";

    // Flow & anomaly
    if(update_flow(key,h->len)) os<<" [ANOMALY]";

    log_msg(os.str());
    if(g_dump_payload && rem>0){
        log_msg("HEX:\n"+hexDump(pkt+offset,rem));
        log_msg("ASCII:"+asciiDump(pkt+offset,rem));
    }
}

//–– Capture Setup ––––––––––––––––––––––––––––––––––––––––––––––––––

pcap_t* open_capture(const std::string& iface, const std::string& bpf) {
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* h = pcap_open_live(iface.c_str(),65536,1,1000,err);
    if(!h) throw std::runtime_error(err);
    if(!bpf.empty()){
        bpf_program fp;
        if(pcap_compile(h,&fp,bpf.c_str(),0,PCAP_NETMASK_UNKNOWN)==-1||
           pcap_setfilter(h,&fp)==-1){
            std::string e=pcap_geterr(h); pcap_freecode(&fp);
            throw std::runtime_error("Filter: "+e);
        }
        pcap_freecode(&fp);
    }
    return h;
}

//–– Signal Handler –––––––––––––––––––––––––––––––––––––––––––––––––

void sigint_handler(int){ g_running=false; }

//–– Main ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––

void print_help(const char* prog){
    std::cout<<"Usage: "<<prog<<" [options]\n"
            <<"  -i <iface>    Interface\n"
            <<"  -f <bpf>      BPF filter\n"
            <<"  -p <pattern>  Payload pattern\n"
            <<"  -v            Verbose\n"
            <<"  -d            Dump payload\n"
            <<"  -l <file>     Log file\n"
            <<"  -h            Help\n";
}

int main(int argc,char*argv[]){
    std::string iface,bpf,pattern,logf;
    for(int i=1;i<argc;++i){
        std::string a=argv[i];
        if(a=="-i"&&i+1<argc) iface=argv[++i];
        else if(a=="-f"&&i+1<argc) bpf = argv[++i];
        else if(a=="-p"&&i+1<argc) g_pattern_filter = argv[++i];
        else if(a=="-v") g_verbose=true;
        else if(a=="-d") g_dump_payload=true;
        else if(a=="-l"&&i+1<argc){ g_log_to_file=true; logf=argv[++i]; }
        else if(a=="-h"){ print_help(argv[0]); return 0; }
        else { std::cerr<<"Unknown "<<a<<"\n"; return 1; }
    }
    if(iface.empty()){
        list_interfaces();
        std::cout<<"Select interface number: "; int n; std::cin>>n;
        pcap_if_t* devs; char err[PCAP_ERRBUF_SIZE];
        pcap_findalldevs(&devs,err);
        for(int i=1;i<n&&devs;devs=devs->next,++i);
        if(!devs){std::cerr<<"Bad iface\n";return 1;}
        iface = devs->name; pcap_freealldevs(devs);
    }

#ifdef _WIN32
    WSADATA wd; WSAStartup(MAKEWORD(2,2),&wd);
    signal(SIGINT,sigint_handler);
#else
    signal(SIGINT,sigint_handler);
#endif

    if(g_log_to_file){
        g_log_file.open(logf,std::ios::app);
        if(!g_log_file){std::cerr<<"Log open fail\n";return 1;}
    }

    std::thread stats([](){
        while(g_running){
            std::this_thread::sleep_for(std::chrono::seconds(10));
            display_flows(10);
        }
    });

    try {
        auto handle = open_capture(iface,bpf);
        log_msg("Start on "+iface+" bpf='"+bpf+"'");
        pcap_loop(handle,0,packet_handler,nullptr);
        pcap_close(handle);
    } catch(std::exception& e){
        std::cerr<<"Error: "<<e.what()<<"\n";
    }

    g_running=false;
    stats.join();
    if(g_log_to_file) g_log_file.close();
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
