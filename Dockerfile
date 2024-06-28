# Use an official Ubuntu as a parent image
FROM ubuntu:20.04

# Set environment variables to non-interactive
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages
RUN apt-get update && \
    apt-get install -y build-essential libpcap-dev libjson-c-dev && \
    apt-get clean

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Compile the C program
RUN gcc -o smb_parser smb_parser.c -lpcap -ljson-c

# Run the smb_parser executable
CMD ["./smb_parser", "smb.pcap"]
