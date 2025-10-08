#include "./include/parser.hpp"
#include "./include/logger.hpp"



bool DHCPPacket::parse(const uint8_t *buffer, size_t len) {
  if (len < 240) {
      LOG_ERROR("minimum length should be at least 240 bytes, but got %d bytes (%s)", len);
      return false;
  }
  op = buffer[0];
  htype = buffer[1];
  hlen = buffer[2];
  hops = buffer[3];

  xid = *(uint32_t *)(buffer + 4);
  secs = *(uint16_t *)(buffer + 8);
  flags = *(uint16_t *)(buffer + 10);
  ciaddr = *(uint32_t *)(buffer + 12);
  yiaddr = *(uint32_t *)(buffer + 16);
  giaddr = *(uint32_t *)(buffer + 20);
  siaddr = *(uint32_t *)(buffer + 24);

  memcpy(chaddr, buffer + 28, 16);

  for (size_t i = 0; i < 64 && buffer[44 + i] != '\0'; i++) {
    sname += (char)buffer[44 + i];
  }
  for (size_t i = 0; i < 128 && buffer[108 + i] != '\0'; ++i) {
    file += (char)buffer[108 + i];
  }
  uint32_t magic = ntohl(*(uint32_t *)(buffer + 236));
  if (magic != DHCP_MAGIC_COOKIE) {
      LOG_ERROR("invalid DHCP magic cookie: got 0x%08x, expected 0x%08x", magic, DHCP_MAGIC_COOKIE);
  }

  const uint8_t *ptrOptions = buffer + 240;
  size_t offset = 0;
  while (ptrOptions[offset] != DHCP_OPT_END) {
    uint8_t code = ptrOptions[offset];
    if (code == DHCP_OPT_PAD) {
      ++offset;
      continue;
    }
    uint8_t optLen = ptrOptions[offset + 1];
    options[code] =
        vector<uint8_t>(ptrOptions + offset + 2,
                        ptrOptions + offset + 2 + optLen); // start, end
    offset += 2 + optLen;
  }

  return true;
}



size_t DHCPPacket::build(uint8_t *buffer, size_t len) {
  if (len < 575) {
      LOG_ERROR("Buffer too small for DHCP packet\n");
    return 0;
  }
  buffer[0] = op;
  buffer[1] = htype;
  buffer[2] = hlen;
  buffer[3] = hops;
  *(uint32_t *)(buffer + 4) = xid;
  *(uint16_t *)(buffer + 8) = secs;
  *(uint16_t *)(buffer + 10) = flags;
  *(uint32_t *)(buffer + 12) = ciaddr;
  *(uint32_t *)(buffer + 16) = yiaddr;
  *(uint32_t *)(buffer + 20) = siaddr;
  *(uint32_t *)(buffer + 24) = giaddr;
  memcpy(buffer + 28, chaddr, 16);

  // add \0?
  memcpy(buffer + 44, sname.data(), min(sname.size(), size_t(64)));
  memcpy(buffer + 108, file.data(), min(file.size(), size_t(128)));

  *(uint32_t *)(buffer + 236) = htonl(DHCP_MAGIC_COOKIE);
  uint8_t *ptrOptions = buffer + 240;

  ssize_t totalLen = 240;

  // [type (1 Byte), length (1 Byte), data]
  for (auto &[code, val] : options) {
    if (code == DHCP_OPT_PAD || code == DHCP_OPT_END)
      continue;
    ptrOptions[0] = code;
    ptrOptions[1] = val.size();
    memcpy(ptrOptions + 2, val.data(), val.size());
    ptrOptions += 2 + val.size();
    totalLen += 2 + val.size();
  }
  *ptrOptions = DHCP_OPT_END;
  totalLen += 1;
  return totalLen;
}

void DHCPPacket::setOp(uint8_t value) {
  if (value != 1 && value != 2) {
    LOG_ERROR(
        "Invalid op code: must be 1 (BOOTREQUEST) or 2 (BOOTREPLY)");
  }
  op = value;
}

void DHCPPacket::setHardwareType(uint8_t type) {
  switch (type) {
  case 1:  // Ethernet
  case 6:  // IEEE 802
  case 7:  // ARCNET
  case 15: // Frame Relay
  case 20: // Serial Line
    htype = type;
    break;
  default:
    LOG_ERROR("Invalid htype: unsupported hardware type");
  }
}
void DHCPPacket::setHardwareLength(uint8_t length) {
    if (length == 0 || length > 16) {
        LOG_ERROR("Invalid hlen: must be 1–16");
    }

    // If Ethernet, length shoud be 6
    if (htype == 1 && length != 6) {
        LOG_ERROR("Invalid hlen for Ethernet: must be 6");
    }

    hlen = length;
}
void DHCPPacket::setHops(uint8_t value) {
    // Usually 0 for clients. Some relay agents increment it.
    // Sanity check: RFC does not restrict, but keeping it small is good.
    if (value > 16) {
        LOG_ERROR("Invalid hops: must be 0–16");
    }
    hops = value;
}
void DHCPPacket::setTransactionID(uint32_t id) {
    // RFC: xid can be any 32-bit number, no strict limit
    xid = htonl(id);;
}

void DHCPPacket::setSeconds(uint16_t value) {
    // RFC doesn’t restrict other than 16-bit, but keep it within range
    secs = htons(value);
}
void DHCPPacket::setFlags(uint16_t value) {
    // Only the broadcast bit (0x8000) is valid, others must be 0
    if (value != 0 && value != DHCP_FLAGS_BROADCAST) {
        LOG_ERROR("Invalid flags: only broadcast (0x8000) or 0 allowed");
    }
    flags = htons(value);
}

void DHCPPacket::setClientIP(const uint32_t &ip) {
    uint32_t ipHost = ntohl(ip);

    if (ipHost != 0 && ((ipHost >= 0xE0000000 && ipHost <= 0xEFFFFFFF) || ipHost == 0xFFFFFFFF))
        LOG_ERROR("Invalid ciaddr: cannot be multicast/broadcast");

    ciaddr = ip;
}
uint8_t DHCPPacket::getMessageType() const {
    auto it = options.find(DHCP_OPT_MESSAGE_TYPE);
      if (it != options.end() && !it->second.empty()) {
          return it->second[0];
      }
      return 0;
}
void DHCPPacket::setClientHWAddr(const uint8_t *addr, size_t len) {
    if (len > 16)
        LOG_ERROR("MAC length cannot exceed 16 bytes");
    hlen = static_cast<uint8_t>(len);
    memset(chaddr, 0, sizeof(chaddr));
    memcpy(chaddr, addr, len);
}
size_t DHCPPacket::getClientHWAddr(uint8_t *out, size_t maxLen) const {
    size_t copyLen = (hlen < maxLen) ? hlen : maxLen;
    memcpy(out, chaddr, copyLen);
    return copyLen;
}

void DHCPPacket::setServerName(const string &name) {
    sname = name;
}

string DHCPPacket::getServerName() const {
    return sname;
}

void DHCPPacket::setBootFile(const string &filename) {
    file = filename;
}

string DHCPPacket::getBootFile() const {
    return file;
}

void DHCPPacket::setYourIP(const uint32_t &ip) {
    uint32_t ipHost = ntohl(ip);


    if (ipHost >= 0xE0000000 && ipHost <= 0xEFFFFFFF || ipHost == 0xFFFFFFFF)
        LOG_ERROR("Invalid yiaddr: cannot be multicast/broadcast");

    yiaddr = ip;
}

void DHCPPacket::setGatewayIP(const uint32_t &ip) {
    uint32_t ipHost = ntohl(ip);

    if (ipHost != 0 && ((ipHost >= 0xE0000000 && ipHost <= 0xEFFFFFFF) || ipHost == 0xFFFFFFFF))
        LOG_ERROR("Invalid giaddr: cannot be multicast/broadcast");

    giaddr = ip;
}

void DHCPPacket::setServerIP(const uint32_t &ip) {
    uint32_t ipHost = ntohl(ip);

    if (ipHost != 0 && ((ipHost >= 0xE0000000 && ipHost <= 0xEFFFFFFF) || ipHost == 0xFFFFFFFF))
        LOG_ERROR("Invalid siaddr: cannot be multicast/broadcast");

    siaddr = ip;
}


uint8_t DHCPPacket::setServerIdentifier(const uint32_t& serverIP) {
    options[DHCP_OPT_SERVER_IDENTIFIER].resize(4);
    memcpy(options[DHCP_OPT_SERVER_IDENTIFIER].data(), &serverIP, 4);
    return DHCP_OPT_SERVER_IDENTIFIER;
}

uint8_t DHCPPacket::setSubnetMask(const uint32_t &ip) {
  options[DHCP_OPT_SUBNET_MASK].resize(4);
  memcpy(options[DHCP_OPT_SUBNET_MASK].data(), &ip, 4);
  return DHCP_OPT_SUBNET_MASK;
}
uint8_t DHCPPacket::setRouter(const uint32_t &ip) {
  options[DHCP_OPT_ROUTER].resize(4);
  memcpy(options[DHCP_OPT_ROUTER].data(), &ip, 4);
  return DHCP_OPT_ROUTER;
}
uint8_t DHCPPacket::setDNS(const vector<uint32_t>& dns) {
    if (dns.empty()) {
        LOG_ERROR("dns list cannot be empty");
    }

    options[DHCP_OPT_DNS].resize(dns.size() * 4);

    uint8_t* ptr = options[DHCP_OPT_DNS].data();

    for (size_t i = 0; i < dns.size(); ++i) {
        uint32_t IP = htonl(dns[i]);
        if(IP == 0) continue;
        memcpy(ptr + (i * 4), &dns[i], 4);
    }

    return DHCP_OPT_DNS;
}
uint8_t DHCPPacket::setHostname(const string &hostname) {
  options[DHCP_OPT_HOST_NAME].resize(hostname.size() + 1);
  memcpy(options[DHCP_OPT_HOST_NAME].data(), hostname.c_str(),
         hostname.size());
  return DHCP_OPT_HOST_NAME;
}
uint8_t DHCPPacket::setDomainName(const string &domainName) {
  if (domainName.empty()) {
    return 0;
  }

  size_t len = domainName.length() + 1;

  options[DHCP_OPT_DOMAIN_NAME].resize(len);

  memcpy(options[DHCP_OPT_DOMAIN_NAME].data(), domainName.c_str(), len);

  return DHCP_OPT_DOMAIN_NAME;
}
uint8_t DHCPPacket::setBroadcastAddress(const uint32_t &ip) {
  options[DHCP_OPT_BROADCAST_ADDRESS].resize(4);
  memcpy(options[DHCP_OPT_BROADCAST_ADDRESS].data(), &ip, 4);
  return DHCP_OPT_BROADCAST_ADDRESS;
}
uint8_t DHCPPacket::setNTPServers(const vector<uint32_t>& ntpServers) {
    if (ntpServers.empty()) {
        LOG_ERROR("NTP server list cannot be empty");
    }

    options[DHCP_OPT_NTP_SERVERS].resize(ntpServers.size() * 4);

    uint8_t* ptr = options[DHCP_OPT_NTP_SERVERS].data();

    for (size_t i = 0; i < ntpServers.size(); ++i) {
        uint32_t netIP = htonl(ntpServers[i]);
        if(netIP == 0) continue;
        memcpy(ptr + (i * 4), &ntpServers[i], 4);
    }

    return DHCP_OPT_NTP_SERVERS;
}


// signed 4-byte integer in network order that tells clients how many seconds
// their timezone differs from UTC (obsolete in RFC 4833)
uint8_t DHCPPacket::setTimeOffset(int32_t offset) {
  int32_t net_offset = htonl(offset);
  options[DHCP_OPT_TIME_OFFSET].resize(4);
  memcpy(options[DHCP_OPT_TIME_OFFSET].data(), &net_offset, 4);
  return DHCP_OPT_TIME_OFFSET;
}
/*used by server to confirm in ACK. */
uint8_t DHCPPacket::setRequestIP(uint32_t ip) {
  options[DHCP_OPT_REQUEST_IP].resize(4);
  memcpy(options[DHCP_OPT_REQUEST_IP].data(), &ip, 4);
  return DHCP_OPT_REQUEST_IP;
}

uint8_t DHCPPacket::setDHCPMessage(uint8_t message) {
  options[DHCP_OPT_MESSAGE_TYPE] = {message};
  return DHCP_OPT_MESSAGE_TYPE;
}


uint8_t DHCPPacket::setLeaseTime(uint32_t seconds) {
  uint32_t net_seconds = htonl(seconds);
  options[DHCP_OPT_LEASE_TIME].resize(4);
  memcpy(options[DHCP_OPT_LEASE_TIME].data(), &net_seconds, 4);
  return DHCP_OPT_LEASE_TIME;
}

uint8_t DHCPPacket::setMessage(const string &message) {
  // RFC 2131: max size is 255
  if (message.size() > 255)
    return 0;
  options[DHCP_OPT_MESSAGE].resize(message.length() + 1);
  memcpy(options[DHCP_OPT_MESSAGE].data(), message.data(), message.size());
  return DHCP_OPT_MESSAGE;
}

uint8_t DHCPPacket::setParameterList(const vector<uint8_t> &list) {
  options[DHCP_OPT_PARAM_REQUEST_LIST] = list;
  return DHCP_OPT_PARAM_REQUEST_LIST;
}


uint8_t DHCPPacket::getOp() const { return op; }
uint8_t DHCPPacket::getHardwareType() const {
    return htype;
}
uint8_t DHCPPacket::getHardwareLength() const {
    return hlen;
}
uint8_t DHCPPacket::getHops() const {
    return hops;
}
uint32_t DHCPPacket::getTransactionID() const { return ntohl(xid); }
uint16_t DHCPPacket::getSeconds() const { return ntohs(secs); }

uint16_t DHCPPacket::getFlags() const { return ntohs(flags); }

uint32_t DHCPPacket::getClientIP() const { return ntohl(ciaddr); }

uint32_t DHCPPacket::getYourIP() const { return ntohl(yiaddr); }

uint32_t DHCPPacket::getGatewayIP() const { return ntohl(giaddr); }

uint32_t DHCPPacket::getServerIP() const { return ntohl(siaddr); }


vector<uint8_t> DHCPPacket::getListParams() const {
  vector<uint8_t> codes;
  auto it = options.find(DHCP_OPT_PARAM_REQUEST_LIST);
   if(it != options.end()){
       for (uint8_t code : it->second) {
           codes.push_back(code);
      }
   }
   return codes;
}
