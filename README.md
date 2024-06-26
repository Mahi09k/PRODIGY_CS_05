# Packet Sniffer Tool

## Overview
This project implements a simple packet sniffer tool in Python that captures and analyzes network packets. The tool displays relevant information such as source and destination IP addresses, protocols, and payload data.

## Features
- Captures network packets.
- Displays source and destination IP addresses.
- Identifies the protocol (TCP, UDP, or other).
- Extracts and displays payload data for TCP and UDP packets.

## Requirements
- Python 3.x
- `scapy` library

## Installation
1. Clone this repository or download the script `packet_sniffer.py`.
2. Install the required library using pip:
    ```sh
    pip install scapy
    ```

## Usage
1. **Run the script with elevated privileges**:
    ```sh
    sudo python packet_sniffer.py
    ```
2. The tool will start capturing and displaying packet information.

### Example Output

Source IP: 192.168.1.2 | Destination IP: 93.184.216.34 | Protocol: TCP
Payload Data: b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'

Source IP: 192.168.1.3 | Destination IP: 192.168.1.2 | Protocol: UDP
Payload Data: b'\x12\x34\x56\x78'


## Disclaimer
This packet sniffer tool is provided for educational purposes only. Unauthorized interception of network traffic is illegal and unethical. Always obtain proper consent and ensure compliance with local laws and regulations when using or developing such tools.

## Note
- **Ethics and legality**: Always use packet sniffers responsibly and ethically. Unauthorized use can lead to severe legal consequences.
- **Transparency**: Inform and get consent from all parties involved before deploying any monitoring software.
- **Security**: Store and handle the collected data securely to prevent misuse or data breaches.
