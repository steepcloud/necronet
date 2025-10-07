#!/bin/bash

# filepath: setup.sh
echo "Setting up Necronet demo environment on Kali Linux..."

# Make scripts executable
chmod +x necronet_demo.sh
chmod +x setup.sh

# Install dependencies
echo "Installing required packages..."
sudo apt update
sudo apt install -y curl netcat-traditional nmap hping3 dnsutils python3 libpcap-dev

# Build the project
echo "Building Necronet..."
make build

echo "Setup complete! Usage:"
echo "  make demo     - Start interactive demo"
echo "  make run-cli  - Run Necronet CLI"
echo "  make help     - Show all options"