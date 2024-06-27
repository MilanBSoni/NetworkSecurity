FROM ubuntu:latest

RUN apt update && apt install -y build-essential libpcap-dev

COPY . /app
WORKDIR /app

RUN gcc -o smb_parser smb_parser.c -lpcap

ENTRYPOINT ["./smb_parser"]
