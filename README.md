# netoverview
 A Python-based tool meant for rapidly gaining high-level statistical insights into the network activities of a PCAP file. 

# NetOverview 🌐🔍

## Rapid Insights into Network Traffic

NetOverview is a Python-based tool designed to provide quick, high-level statistical insights into network activities captured in PCAP files. 

---

### 🚀 Features

- **Swift Analysis**: Quickly process PCAP files to extract key network statistics.
- **High-Level Insights**: Get a bird's-eye view of network activities without drowning in details.
- **Blue Team Oriented**: Tailored for cybersecurity professionals defending networks.
- **PCAP(NG) Friendly**: Works directly with pcap and pcapng files, the industry standard for packet captures.

---

### 🛠 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netoverview.git

# Navigate to the project directory
cd netoverview
```

---

### 🏃‍♂️ Quick Start

```bash
python netoverview.py path/to/your/capture.pcap
```

---

### 📊 Sample Output

```
NetOverview Analysis Report
---------------------------
File: capture.pcap
Packets Analyzed: 10,000
Time Range: 2023-09-19 14:30:15 - 2023-09-19 15:45:22

Top 5 Source IPs:
1. 192.168.1.100 (2,345 packets)
2. 10.0.0.5 (1,832 packets)
3. 172.16.0.1 (956 packets)
...

Protocol Distribution:
- TCP: 65%
- UDP: 30%
- ICMP: 5%

Unusual Patterns Detected:
- High volume of traffic from 192.168.1.100 to port 4444
- Spike in ICMP traffic at 15:30:00
```

---

### 🤝 Contributing

I welcome contributions! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to submit pull requests, report issues, or request features.

---

### 📜 License

This project is licensed under the GNU GPLv3 License - see the [LICENSE.md](LICENSE.md) file for details.