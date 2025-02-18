### 🛠 Installation

```bash
# Clone the repository
git clone https://github.com/tatescode/pcapprowler

# Navigate to the project directory
cd netoverview
```

---

### Quick Start

```bash
python PcapProwler.py path/to/your/capture.pcap
```

---

### 📊 Sample Output

```
Analysis Report
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

### 📜 License

This project is licensed under the GNU GPLv3 License - see the [LICENSE.md](LICENSE.md) file for details.
