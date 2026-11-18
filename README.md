# CodeAlpha Cybersecurity Internship

Hands-on projects completed during my **Cybersecurity internship at CodeAlpha**.
The repository contains two tasks: a packet sniffer built with Python and Scapy, and an interactive phishing-awareness training module.

| # | Task | Folder | Dependencies |
|---|------|--------|--------------|
| 1 | Basic Network Sniffer | [`task1_network_sniffer`](task1_network_sniffer) | Scapy |
| 2 | Phishing Awareness Training | [`task2_phishing_awareness`](task2_phishing_awareness) | Standard library only |

---

## Repository structure

```
CodeAlpha_internship/
├── task1_network_sniffer/
│   └── network_sniffer.py
├── task2_phishing_awareness/
│   └── phishing_training.py
├── tests/
│   └── test_phishing.py
├── requirements.txt
├── .gitignore
├── .gitattributes
├── LICENSE
└── README.md
```

## Setup

```bash
git clone https://github.com/<your-username>/CodeAlpha_internship.git
cd CodeAlpha_internship

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Task 1 also needs system-level packet-capture support:

- **Windows:** install [Npcap](https://npcap.com) and run the terminal as Administrator.
- **Linux:** run with `sudo`; if BPF filters fail, install libpcap (`sudo apt install libpcap-dev`).
- **macOS:** run with `sudo` (libpcap is built in).

Task 2 needs nothing beyond Python 3.8+.

---

## Task 1: Basic Network Sniffer

### Objective
Build a tool that captures live network traffic and shows how data moves through a network, including the structure of packets and the protocols they carry.

### What it does
- Captures packets in real time using **Scapy**.
- Decodes each layer and prints:
  - **Layer 2:** source and destination MAC addresses
  - **Layer 3:** source and destination IPv4/IPv6 addresses, TTL, and ARP requests/replies
  - **Layer 4:** TCP ports, flags (SYN, ACK, FIN...) and sequence numbers; UDP ports and length; ICMP type and code
  - **Application hints:** DNS query names, plus HTTP and HTTPS/TLS identification by port
  - **Payload:** hex dump and printable-ASCII preview of the first 64 bytes
- Prints a **protocol statistics summary** (count and percentage per protocol) when the capture ends.
- Supports BPF filters, interface selection, packet limits and saving to a `.pcap` file.

### Usage

```bash
sudo python3 task1_network_sniffer/network_sniffer.py                       # capture until Ctrl+C
sudo python3 task1_network_sniffer/network_sniffer.py -c 20                 # capture 20 packets
sudo python3 task1_network_sniffer/network_sniffer.py -i eth0 -f "tcp port 80"
sudo python3 task1_network_sniffer/network_sniffer.py -c 50 -w capture.pcap # save to a pcap file
```

| Flag | Description |
|------|-------------|
| `-i`, `--interface` | Interface to sniff on (default: Scapy's default) |
| `-c`, `--count` | Number of packets to capture (`0` = until Ctrl+C) |
| `-f`, `--filter` | BPF filter, e.g. `"tcp port 80"` or `"icmp"` |
| `-w`, `--write` | Save captured packets to a `.pcap` file (open in Wireshark) |

### Output format (illustrative)

```
======================================================================
Packet #1  |  14:32:07.481  |  74 bytes
----------------------------------------------------------------------
  MAC  : aa:bb:cc:dd:ee:ff  ->  11:22:33:44:55:66
  IP   : 192.168.1.10  ->  93.184.216.34   (TTL=64)
  TCP  : port 51514  ->  80   flags=[SYN]  seq=1234567890
  Protocol: HTTP
  Payload: none
```

### Report

**Approach.** Scapy's `sniff()` hands every packet to a callback (`process_packet`). The callback checks which layers are present with `haslayer()` and prints each one from the data link layer up to the application layer. Packets are not stored in memory during capture; they are only collected for the optional `.pcap` export.

**Key concepts learned**
- The layered (OSI/TCP-IP) structure of a packet and how encapsulation works.
- The TCP flag sequence (SYN, SYN-ACK, ACK) that starts a connection.
- How ARP maps IP addresses to MAC addresses on a local network.
- Using BPF filters to capture only relevant traffic.
- Why unencrypted protocols such as plain HTTP expose their payload, while TLS traffic shows only encrypted bytes.

**Limitations and possible improvements**
- Application protocols are identified by port number, not by inspecting the content.
- Only the first 64 bytes of each payload are displayed.
- Future work: TCP stream reassembly, a basic anomaly alert (for example port-scan detection), and a live statistics dashboard.

> **Legal and ethical notice:** only capture traffic on networks you own or are explicitly authorised to monitor. Capture files can contain sensitive data, so `.pcap` files are excluded from this repository via `.gitignore`.

---

## Task 2: Phishing Awareness Training

### Objective
Create an educational module that teaches users to recognise and avoid phishing attacks, covering email, websites and social-engineering tactics.

### What it does
An interactive, menu-driven terminal program with these sections:

1. **What is phishing?** Email phishing, spear phishing, whaling, smishing, vishing and quishing.
2. **Recognising phishing emails:** seven red flags, with an annotated sample phishing email.
3. **Recognising fake websites:** lookalike domains, subdomain tricks, homograph attacks, and why the padlock does not mean safe.
4. **Hands-on URL red-flag checker:** type any URL and see which warning signs it triggers.
5. **Social engineering tactics:** authority, urgency, fear, greed, pretexting, baiting, tailgating and MFA fatigue.
6. **Real-world examples:** RSA (2011), Target (2013), Google/Facebook invoice scam, Twitter (2020).
7. **Best practices:** password managers, passkeys, MFA, updates, and what to do after clicking a bad link.
8. **Interactive quiz:** 8 shuffled questions with instant feedback, explanations and a final score.

### Usage

```bash
python3 task2_phishing_awareness/phishing_training.py
```

### URL checker heuristics
`analyze_url()` flags the following warning signs:

| Check | Example |
|-------|---------|
| Not using HTTPS | `http://...` |
| Raw IP address as the host | `http://192.168.4.7/login` |
| `@` in the address | `http://bank.com@evil.com` |
| Punycode / homograph domain | `xn--...` |
| Excessive subdomains | `a.b.c.d.example.com` |
| Brand name inside a different domain | `paypal.com.verify-login.net` |
| Digits swapped for letters | `paypa1`, `micros0ft`, `faceb00k` |
| Many hyphens in the domain | `secure-account-update.com` |
| Commonly abused TLDs | `.zip`, `.xyz`, `.top`, `.click` |
| Very long URLs | over 100 characters |
| Credential words in the address | `login`, `verify`, `secure`, `update` |

### Report

**Approach.** The module uses only the standard library, so it runs anywhere without installation. Lesson content is separated from logic: each lesson is its own function, the quiz is a data list, and a menu table maps options to functions. The quiz shuffles both the question order and the answer options on every run.

**Key concepts learned**
- Most phishing succeeds by exploiting human psychology (urgency, authority, fear) rather than technology.
- Reading a domain correctly (right to left, up to the first single slash) defeats most lookalike-link tricks.
- HTTPS shows that a connection is encrypted, not that a site is trustworthy.
- Phishing-resistant MFA (passkeys and hardware keys) beats SMS codes.
- Reporting an incident quickly protects other people as well as yourself.

**Testing.** The URL checker has unit tests covering suspicious and legitimate URLs:

```bash
python -m unittest discover tests -v
```

**Limitations and possible improvements.** The checker is heuristic-based and educational; it is not a replacement for a real URL-reputation service. It could be extended with a domain-age lookup, a larger brand list, or a web front end.

---

## Skills demonstrated
Python, packet analysis (Scapy), TCP/IP and OSI model, BPF filtering, command-line tool design (`argparse`), security awareness training, social engineering concepts, unit testing.

## Disclaimer
These projects are for **educational purposes only**. Use them only on systems and networks you own or have written permission to test.

## License
Released under the [MIT License](LICENSE).

## Author
**[Your Name]**: Cybersecurity Intern at [CodeAlpha](https://www.codealpha.tech)
[GitHub](https://github.com/<your-username>) | [LinkedIn](https://www.linkedin.com/in/<your-profile>)
