# SMB Parser

## Description
This program parses SMBv2 packets from a given pcap file, extracts attachments and metadata.

## Requirements
- Ubuntu
- libpcap

## Usage

### Compiling
```sh
gcc -o smb_parser smb_parser.c -lpcap
