# PCAP Editor

A client-side web application for viewing, filtering, and editing packet details in PCAP files directly in your browser. All processing happens locally - your data never leaves your machine.

Application is available here: https://www.h21lab.com/applications/pcap-editor

## Features

- **Local Processing:** All PCAP files are processed entirely in your browser. Data is never uploaded to any server.
- **Deep Dissection:** Leverages Wireshark's powerful dissection engine via WebAssembly.
- **Packet Editing:** Edit field values directly in the decoded detail view.
- **Python Editor:** Human-readable Python code for packet encoding using Scapy, Pycrate, and other libraries. Edit protocol fields and regenerate packets.
- **Filtering:** Use Wireshark display filters to narrow down packets.
- **Export:** Download the modified PCAP file.

## Supported Protocols

The editor supports 100+ protocols through Scapy and Pycrate encoding libraries:

### Networking
Ethernet, IP, IPv6, TCP, UDP, SCTP, ICMP, ICMPv6, ARP, DNS, DHCP/BOOTP

### Routing & Switching
BGP, OSPF, EIGRP, RIP, ISIS, MPLS, VRRP, HSRP, STP, LLDP, CDP, BFD

### Tunneling & VPN
GRE, VXLAN, L2TP, PPP, PPPoE, OpenVPN, IPSec (AH, ESP)

### IoT & Wireless
MQTT, CoAP, ZigBee, 6LoWPAN, IEEE 802.15.4, LoRaWAN

### Industrial / SCADA
Modbus, DNP3, S7Comm (Siemens), IEC 104, MMS (IEC 61850)

### Automotive
UDS (Unified Diagnostic Services), DoIP, SOME/IP

### Telecom / Mobile
SIGTRAN (M3UA, M2UA, MTP3, ISUP), SCCP, TCAP, MAP, CAMEL/CAP, Diameter, GTP/GTPv2, PFCP, S1AP, NGAP, NAS-5G, NAS-LTE, SMS

### VoIP & Media
SIP, RTP, RTSP, MGCP, H.265

### Enterprise & Database
SMB/SMB2, DCERPC, LDAP, Kerberos, NTLM, MySQL, TDS (MS SQL), NFS, RADIUS

### Application Layer
HTTP, HTTP/2, FTP, SMTP, POP3, IMAP, SSH, Telnet, TFTP, TLS

## Getting Started

### Prerequisites

- Node.js (v16 or later)
- npm

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/H21lab/pcap-editor.git
   cd pcap-editor
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm start
   ```

4. **Build for production:**
   ```bash
   npm run build
   ```

## How It Works

1. **Upload a PCAP file** - The file is loaded entirely in your browser
2. **Packets are dissected** using Wireshark's WASM-based dissector (Wiregasm)
3. **View packet details** in the tree view, just like in Wireshark
4. **Edit packets** using either:
   - The hex editor for raw byte manipulation
   - The Python editor for human-readable field editing
5. **Export** your modified PCAP file

The Python editor generates executable Python code that reconstructs each packet layer by layer. You can modify field values directly in the code and apply changes to update the packet.

## Privacy

This application is entirely client-based. Your PCAP files are processed locally in your browser and are never uploaded to any server.

## Disclaimer

This software is provided "as is" without warranty of any kind. Editing packets may result in invalid checksums (IP, TCP, UDP) or malformed protocol structures if the new values do not adhere to protocol specifications. Always review your exported PCAPs carefully.

## Attributions

This project builds upon the work of several excellent open-source projects:

- **[Wiregasm](https://github.com/good-tools/wiregasm)** - WebAssembly port of Wireshark dissectors
- **[Wireshark](https://www.wireshark.org/)** - The world's foremost network protocol analyzer
- **[Scapy](https://github.com/secdev/scapy)** - Powerful Python-based interactive packet manipulation library
- **[Pycrate](https://github.com/pycrate-org/pycrate)** - Python library for encoding/decoding ASN.1/PER/BER structures and telecom protocols
- **[Pyodide](https://pyodide.org/)** - Python runtime for WebAssembly

### Additional Libraries

- React and Material-UI for the user interface
- Monaco Editor for the Python code editor
- react-resizable-panels for the split-pane layout

Any third-party code included in this project remains under its original license as specified by the respective authors.

## License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.

## Copyright

Copyright H21 lab.
