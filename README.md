# DHCP Spoofing & MitM Tool

This project is a C++ tool built for educational purposes to demonstrate a classic network attack. It performs **DHCP Spoofing** to assign a victim a malicious network configuration, followed by a **Man-in-the-Middle (MitM)** attack to intercept their outbound traffic.

The tool works by listening for DHCP `DISCOVER` packets from a specific target. It then races against the legitimate DHCP server to reply with a malicious `OFFER` and `ACK`, assigning itself as the victim's default gateway. Once compromised, it forwards the victim's traffic to the real router to maintain connectivity, allowing for passive observation.

**Disclaimer:** This tool is for educational and research purposes only. Unauthorized attacks on networks are illegal. Use this code responsibly in a controlled lab environment.

## How It Works

1.  **Configuration:** The user provides network details (target MAC, router MAC, attacker IP, etc.).
2.  **DHCP Spoofing:** The `poisoning` thread listens for DHCP requests from the target and sends a fake reply, setting the attacker's machine as the gateway.
3.  **Traffic Interception:** The `relayTraffic` thread captures all outbound packets from the victim, logs them, and forwards them to the legitimate router.
## How to Compile

This project requires `g++` and the `libpcap` library. You can compile the project using the following command:

```bash
g++ main.cpp parser.cpp poison.cpp ./include/logger.hpp -o dhcp -lpcap 
```
## To-Do

-   [ ] **Implement Full-Duplex MitM:** Add ARP spoofing functionality to poison the router's ARP cache as well, allowing for interception of traffic in both directions (client-to-router and router-to-client).
-   [ ] **DNS Spoofing:** Intercept DNS queries from the victim and return a fake IP address to redirect them to a malicious server.
-   [ ] **SSL Stripping:** Add a module to attempt to downgrade HTTPS connections to HTTP for capturing plaintext data.
-   [ ] **Multi-Victim Support:** Refactor the code to manage and attack multiple targets simultaneously.
-   [ ] **Improve User Interface:** Replace the command-line prompts with a more interactive Text-based User Interface (TUI).

## Learn More & See It in Action

*   **Blog Post:** For a detailed breakdown of the code, the attack theory, and defense mechanisms, you can [read the full blog post here](https://portfolio-three-alpha-27.vercel.app/blogs/dhcp-spoofer ).

*   **Demo Video:** Watch a live demonstration of the attack on YouTube.
    *   **[Watch Demo](https://www.youtube.com/watch?v=Gr-7yTVQwCM )**
