#pragma once
#include <arpa/inet.h> // Functions for manipulating IP addresses (e.g., inet_ntoa, inet_pton, htonl/htons).
#include <cstdint> // Fixed-width integer types (e.g., uint8_t, int32_t, uint64_t).
#include <cstring> // C-style string and memory handling (e.g., memcpy, memset, strlen).
#include <map>         // Ordered key-value container (std::map).
#include <string>      // std::string class and related functions.
#include <sys/types.h> // Basic system data types (e.g., pid_t, size_t, ssize_t).
#include <vector>      // Dynamic array container (std::vector).

using namespace std;

#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCP_FLAGS_BROADCAST 0x8000

/* Common DHCP Option Codes */
#define DHCP_OPT_PAD 0           /* Padding, no length or value */
#define DHCP_OPT_SUBNET_MASK 1   /* Subnet mask (4 bytes) */
#define DHCP_OPT_ROUTER 3        /* Router/gateway IPs (multiple of 4 bytes) */
#define DHCP_OPT_DNS 6           /* DNS server IPs (multiple of 4 bytes) */
#define DHCP_OPT_HOST_NAME 12    /* Client hostname (variable length) */
#define DHCP_OPT_DOMAIN_NAME 15  /* Domain name (variable length) */
#define DHCP_OPT_REQUESTED_IP 50 /* Requested IP address (4 bytes) */
#define DHCP_OPT_LEASE_TIME 51   /* Lease duration in seconds (4 bytes) */
#define DHCP_OPT_MESSAGE_TYPE 53 /* DHCP message type (1 byte) */
#define DHCP_OPT_SERVER_IDENTIFIER 54  /* DHCP server IP (4 bytes) */
#define DHCP_OPT_PARAM_REQUEST_LIST 55 /* Parameter request list (variable) */
#define DHCP_OPT_MESSAGE                                                       \
  56 /* DHCP message (var)Error message for NAK or Inform responses. Value:    \
ASCII string (min 1 char). Used to explain NAK reasons.  */
#define DHCP_OPT_END 255              /* End of options */
#define DHCP_OPT_TIME_OFFSET 2        /* Time Offset (4 bytes) */
#define DHCP_OPT_REQUEST_IP 50        /* Requested IP address (4 bytes) */
#define DHCP_OPT_BROADCAST_ADDRESS 28 /* Broadcast Address (4 bytes) */
#define DHCP_OPT_NTP_SERVERS 42       /* NTP Servers (multiple of 4 bytes) */
#define DHCP_OPT_NETBIOS_NAME_SERVER                                           \
  44 /* NetBIOS Name Server (multiple of 4 bytes) */
#define DHCP_OPT_NETBIOS_SCOPE 47  /* NetBIOS Scope (variable length) */
#define DHCP_OPT_INTERFACE_MTU 26  /* Interface MTU (2 bytes) */
#define DHCP_OPT_DOMAIN_SEARCH 119 /* Domain Search List (variable length) */
#define DHCP_OPT_CLASSLESS_STATIC_ROUTE                                        \
  121 /* Classless Static Route (variable length) */

// op header
#define BOOTREQUEST 1
#define BOOTREPLY 2

/* DHCP Message Types (for Option 53) */
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8


class DHCPPacket {

private:
  uint8_t op;
  // Operation Code
  // - Client: always 1 (BOOTREQUEST)
  // - Server: always 2 (BOOTREPLY)

  uint8_t htype;
  // Hardware Type
  // - Client: hardware type (Ethernet = 1)
  // - Server: echoes back same value

  uint8_t hlen;
  // Hardware Address Length
  // - Client: length of MAC (Ethernet = 6)
  // - Server: echoes back same value

  uint8_t hops;
  // Relay Hops
  // - Client: always 0
  // - Relay agent: increments if forwarding
  // - Server: usually ignores

  uint32_t xid;
  // Transaction ID
  // - Client: random number for this exchange
  // - Server: copies back in all replies

  uint16_t secs;
  // Seconds Elapsed
  // - Client: time since DHCP process started
  // - Server: may ignore or use for prioritization

  uint16_t flags;
  // Flags
  // - Client: set broadcast flag (bit 0) if cannot receive unicast
  // - Server: echoes back, uses it to decide broadcast/unicast reply

  uint32_t ciaddr;
  // Client IP Address
  // - Client: 0.0.0.0 if no lease yet
  //           filled if renewing/rebinding with known IP
  // - Server: ignored if 0

  uint32_t yiaddr;
  // Your IP Address
  // - Client: always 0 in requests
  // - Server: fills with offered/leased IP

  uint32_t giaddr;
  // Gateway/Relay Agent IP
  // - Client: 0 if direct
  // - Relay agent: fills with its IP
  // - Server: uses it to send reply via relay

  uint32_t siaddr;
  // Server IP Address (next server)
  // - Client: 0
  // - Server: may set to its own IP or PXE/TFTP server

  uint8_t chaddr[16];
  // Client Hardware Address
  // - Client: fills with its MAC
  // - Server: echoes back to identify client

  string sname = "";
  // Server Host Name
  // - Client: empty
  // - Server: optional, may fill with server hostname

  string file = "";
  // Boot File Name
  // - Client: empty
  // - Server: optional, may fill with PXE/boot file name

  map<uint8_t, vector<uint8_t>> options;
  // DHCP Options (Type-Length-Value)
  // - Client: includes DHCP message type (Discover/Request),
  //           parameter request list (DNS, router, subnet),
  //           hostname, requested IP, client identifier.
  // - Server: includes DHCP message type (Offer/Ack),
  //           server identifier, lease time, subnet mask,
  //           router, DNS servers, domain name, broadcast address, etc.
public:

  uint8_t getMessageType() const ;


  void setOp(uint8_t value);
  uint8_t getOp() const;

  void setHardwareType(uint8_t type);
  uint8_t getHardwareType() const;

  void setHardwareLength(uint8_t length);
  uint8_t getHardwareLength() const;

  void setHops(uint8_t value);
  uint8_t getHops() const;

  void setTransactionID(uint32_t id);
  uint32_t getTransactionID() const;

  void setSeconds(uint16_t secs);
  uint16_t getSeconds() const;

  void setFlags(uint16_t flags);
  uint16_t getFlags() const;

  void setClientIP(const uint32_t &ip);
  uint32_t getClientIP() const;

  void setYourIP(const uint32_t &ip);
  uint32_t getYourIP() const;

  void setGatewayIP(const uint32_t &ip);
  uint32_t getGatewayIP() const;

  void setServerIP(const uint32_t &ip);
  uint32_t getServerIP() const;

  void setClientHWAddr(const uint8_t *addr, size_t len);
  size_t getClientHWAddr(uint8_t *out, size_t maxLen) const;
  void setServerName(const string &name);
  string getServerName() const;

  void setBootFile(const string &filename);
  string getBootFile() const;



  // const uint8_t *buffer, size_t len
  bool parse(const uint8_t *buffer, size_t len);

  void print() const;
  size_t build(uint8_t *buffer, size_t len);
  // getters
  void getParameterList(vector<int> &list);
  // setters
  void setParamsWithCallback(void (*func)(int)) const;
  vector<uint8_t> getListParams() const ;
  uint8_t setSubnetMask(const uint32_t &ip);
  uint8_t setRouter(const uint32_t &ip);
  uint8_t setDNS(const vector<uint32_t>& dns);
  uint8_t setHostname(const string &hostname);
  uint8_t setDomainName(const string &domainName);
  uint8_t setBroadcastAddress(const uint32_t &ip);
  // TODO: more than one ip;
  uint8_t setNTPServers(const vector<uint32_t>& ntpServers);
  // signed 4-byte integer in network order that tells clients how many seconds
  // their timezone differs from UTC (obsolete in RFC 4833)
  uint8_t setTimeOffset(int32_t offset);
  /*used by server to confirm in ACK. */
  uint8_t setRequestIP(uint32_t ip);
  uint8_t setDHCPMessage(uint8_t message);
  uint8_t setServerIdentifier(const uint32_t &ip);
  uint8_t setLeaseTime(uint32_t seconds);
  uint8_t setMessage(const string &message);
  /* Parameter Request List (server response with supported options) */
  uint8_t setParameterList(const vector<uint8_t> &list);
};
