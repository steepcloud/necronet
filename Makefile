.PHONY: build run demo clean install-deps help

# Default target
all: build

# Build the project
build:
	@echo "Building Necronet..."
	zig build

# Run with GUI
run: build
	@echo "Starting Necronet with GUI..."
	./zig-out/bin/necronet

# Run without GUI (CLI mode)
run-cli: build
	@echo "Starting Necronet in CLI mode..."
	sudo ./zig-out/bin/necronet --no-gui

# Make demo script executable and run it
demo: build
	@echo "Setting up demo environment..."
	chmod +x necronet_demo.sh
	./necronet_demo.sh

# Install required dependencies for Kali Linux
install-deps:
	@echo "Installing dependencies for Kali Linux..."
	sudo apt update
	sudo apt install -y curl netcat-traditional nmap hping3 dnsutils python3 libpcap-dev

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf zig-out/
	rm -rf zig-cache/

# Quick test to verify everything works
test: build
	@echo "Running quick functionality test..."
	@echo "Testing interface enumeration..."
	sudo ./zig-out/bin/necronet --list-interfaces || echo "Interface listing failed"

# Development build with debug info
debug: 
	@echo "Building with debug information..."
	zig build -Doptimize=Debug

# Release build
release:
	@echo "Building release version..."
	zig build -Doptimize=ReleaseFast

# Install system-wide (requires root)
install: build
	@echo "Installing Necronet system-wide..."
	sudo cp zig-out/bin/necronet /usr/local/bin/
	sudo chmod +x /usr/local/bin/necronet
	@echo "Necronet installed to /usr/local/bin/"

# Uninstall system-wide
uninstall:
	@echo "Removing Necronet from system..."
	sudo rm -f /usr/local/bin/necronet

# Set capabilities for non-root packet capture
set-caps: build
	@echo "Setting capabilities for packet capture..."
	sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/necronet
	@echo "You can now run Necronet without sudo"

# Show help
help:
	@echo "Necronet Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build        - Build the project"
	@echo "  run          - Run with GUI"
	@echo "  run-cli      - Run in CLI mode (requires sudo)"
	@echo "  demo         - Start interactive demo script"
	@echo "  install-deps - Install required dependencies"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run basic functionality test"
	@echo "  debug        - Build with debug information"
	@echo "  release      - Build optimized release version"
	@echo "  install      - Install system-wide (requires sudo)"
	@echo "  uninstall    - Remove system installation"
	@echo "  set-caps     - Set capabilities for non-root capture"
	@echo "  help         - Show this help message"