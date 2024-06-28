# SMB Parser Project

This project reads SMBv2 packets from a pcap file, extracts attachments, and generates metadata in JSON format.

## Prerequisites

- `libpcap-dev`
- `libjson-c-dev`

## Running the Program Natively

1. **Install Dependencies**:
   ```sh
   sudo apt-get update
   sudo apt-get install -y build-essential libpcap-dev libjson-c-dev
