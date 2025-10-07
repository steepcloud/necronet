#!/bin/bash

# filepath: necronet_demo.sh
###############################################################################
# Necronet Security Testing Demo Script
# 
# This script provides an interactive menu for testing various security
# scenarios with the Necronet intrusion detection system.
###############################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NECRONET_BIN="./zig-out/bin/necronet"
TEST_SERVER="localhost"
TEST_PORT="8000"
INTERFACE="any"

print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    NECRONET DEMO SUITE                      ║"
    echo "║              Network Security Testing Tool                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_menu() {
    echo -e "${CYAN}┌─ ATTACK CATEGORIES ─────────────────────────────────────────┐${NC}"
    echo -e "${GREEN} 1)${NC} Web Application Attacks (SQL Injection, XSS)"
    echo -e "${GREEN} 2)${NC} Network Scanning & Port Enumeration"
    echo -e "${GREEN} 3)${NC} DoS & Network Flooding Attacks"
    echo -e "${GREEN} 4)${NC} Protocol Anomalies & Malformed Packets"
    echo -e "${GREEN} 5)${NC} Backdoor & Malware Communication"
    echo -e "${GREEN} 6)${NC} Run All Attack Scenarios (Demo Mode)"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo -e "${YELLOW} s)${NC} Start Necronet Capture"
    echo -e "${YELLOW} k)${NC} Stop Necronet (Kill Process)"
    echo -e "${YELLOW} h)${NC} Setup HTTP Test Server"
    echo -e "${RED} q)${NC} Quit"
    echo
}

check_dependencies() {
    local missing=()
    
    # Check required tools
    for tool in curl nc nmap hping3 dig python3; do
        if ! command -v $tool &> /dev/null; then
            missing+=($tool)
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Missing required tools: ${missing[*]}${NC}"
        echo -e "${YELLOW}Install with: sudo apt install curl netcat-traditional nmap hping3 dnsutils python3${NC}"
        read -p "Continue anyway? (y/N): " continue_choice
        if [[ ! $continue_choice =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

start_necronet() {
    echo -e "${GREEN}Starting Necronet capture...${NC}"
    echo -e "${YELLOW}Command: sudo $NECRONET_BIN --no-gui${NC}"
    echo -e "${CYAN}Select interface: $INTERFACE (usually option 1)${NC}"
    echo -e "${CYAN}Filter: Leave blank for all traffic${NC}"
    echo
    sudo $NECRONET_BIN --no-gui
}

kill_necronet() {
    echo -e "${RED}Stopping Necronet...${NC}"
    sudo pkill -f necronet
    echo -e "${GREEN}Necronet processes terminated${NC}"
}

setup_http_server() {
    echo -e "${GREEN}Setting up HTTP test server on port $TEST_PORT...${NC}"
    echo -e "${YELLOW}Command: python3 -m http.server $TEST_PORT${NC}"
    echo -e "${CYAN}Server will run in background. Access via http://localhost:$TEST_PORT${NC}"
    echo
    
    # Kill existing server if running
    pkill -f "python3 -m http.server $TEST_PORT" 2>/dev/null
    
    # Start new server in background
    python3 -m http.server $TEST_PORT > /dev/null 2>&1 &
    local server_pid=$!
    echo -e "${GREEN}HTTP server started (PID: $server_pid)${NC}"
    sleep 2
}

web_attacks() {
    echo -e "${PURPLE}═══ WEB APPLICATION ATTACKS ═══${NC}"
    
    local attacks=(
        "Basic HTTP Request (Low)|curl \"http://$TEST_SERVER:$TEST_PORT/\""
        "HTTP OPTIONS Method (Low)|curl -X OPTIONS \"http://$TEST_SERVER:$TEST_PORT/\""
        "HTTP TRACE Method (Low)|curl -X TRACE \"http://$TEST_SERVER:$TEST_PORT/\""
        "Multiple Small Requests (Low)|for i in {1..5}; do curl -s \"http://$TEST_SERVER:$TEST_PORT/\" > /dev/null; done"
        "Basic SQL Injection|curl \"http://$TEST_SERVER:$TEST_PORT/?id=1%27%20OR%201=1--\""
        "UNION SQL Injection|curl \"http://$TEST_SERVER:$TEST_PORT/?query=SELECT%20*%20FROM%20users%20UNION%20SELECT%20username,password%20FROM%20users--\""
        "Time-based SQL Injection|curl \"http://$TEST_SERVER:$TEST_PORT/?id=1%27%20AND%20SLEEP(5)--\""
        "Error-based SQL Injection|curl \"http://$TEST_SERVER:$TEST_PORT/?id=1%27%20AND%20convert(int,@@version)--\""
        "Basic XSS Script Tag|curl \"http://$TEST_SERVER:$TEST_PORT/?input=%3Cscript%3Ealert(1)%3C/script%3E\""
        "XSS IMG Onerror|curl \"http://$TEST_SERVER:$TEST_PORT/?input=%3Cimg%20src=x%20onerror=alert(1)%3E\""
        "JavaScript Protocol XSS|curl \"http://$TEST_SERVER:$TEST_PORT/?url=javascript:alert(document.cookie)\""
        "Oversized URL Attack|curl \"http://$TEST_SERVER:$TEST_PORT/$(python3 -c 'print("A"*1000)')\""
        "Command Injection (Critical)|curl \"http://$TEST_SERVER:$TEST_PORT/?cmd=bash%20-i%20test\""
        "System Execution (Critical)|curl \"http://$TEST_SERVER:$TEST_PORT/?exec=whoami\""
        "File Access (Critical)|curl \"http://$TEST_SERVER:$TEST_PORT/?file=test\""
        "Information Gathering (Critical)|curl \"http://$TEST_SERVER:$TEST_PORT/?info=data\""
        "Multiple Critical Tests|curl \"http://$TEST_SERVER:$TEST_PORT/?cmd=test\" && curl \"http://$TEST_SERVER:$TEST_PORT/?exec=ls\" && curl \"http://$TEST_SERVER:$TEST_PORT/?file=passwd\""
    )
    
    for attack in "${attacks[@]}"; do
        local name="${attack%%|*}"
        local command="${attack##*|}"
        
        echo -e "${CYAN}┌─ $name${NC}"
        echo -e "${YELLOW}│ Command: $command${NC}"
        echo -e "${CYAN}└─${NC}"
        
        read -p "Execute this attack? (y/N/s=skip all): " choice
        case $choice in
            [Yy]* )
                echo -e "${GREEN}Executing...${NC}"
                eval $command
                echo
                sleep 1
                ;;
            [Ss]* )
                echo -e "${YELLOW}Skipping remaining web attacks${NC}"
                break
                ;;
            * )
                echo -e "${YELLOW}Skipped${NC}"
                ;;
        esac
        echo
    done
}

network_attacks() {
    echo -e "${PURPLE}═══ NETWORK SCANNING ATTACKS ═══${NC}"
    
    local attacks=(
        "Horizontal Port Scan|sudo nmap -T4 -p 1-50 $TEST_SERVER"
        "Suspicious Ports Scan|sudo nmap -sT -p 1337,4444,5554,6666,8080,12345,31337 $TEST_SERVER"
        "TCP Connect Scan|sudo nmap -sT -p 80,443,22,21,25 $TEST_SERVER"
        "Stealth SYN Scan|sudo nmap -sS -p 1-100 $TEST_SERVER"
        "UDP Port Scan|sudo nmap -sU -p 53,67,68,123,161 $TEST_SERVER"
        "Service Version Detection|sudo nmap -sV -p 22,80,443 $TEST_SERVER"
    )
    
    for attack in "${attacks[@]}"; do
        local name="${attack%%|*}"
        local command="${attack##*|}"
        
        echo -e "${CYAN}┌─ $name${NC}"
        echo -e "${YELLOW}│ Command: $command${NC}"
        echo -e "${CYAN}└─${NC}"
        
        read -p "Execute this attack? (y/N/s=skip all): " choice
        case $choice in
            [Yy]* )
                echo -e "${GREEN}Executing...${NC}"
                eval $command
                echo
                sleep 2
                ;;
            [Ss]* )
                echo -e "${YELLOW}Skipping remaining network attacks${NC}"
                break
                ;;
            * )
                echo -e "${YELLOW}Skipped${NC}"
                ;;
        esac
        echo
    done
}

dos_attacks() {
    echo -e "${PURPLE}═══ DoS & FLOODING ATTACKS ═══${NC}"
    echo -e "${RED}WARNING: These attacks may impact system performance${NC}"
    
    local attacks=(
        "TCP SYN Flood (Limited)|sudo hping3 -S -p 80 -c 50 --fast $TEST_SERVER"
        "UDP Flood (Limited)|sudo hping3 --udp -p 53 -c 30 --fast $TEST_SERVER"
        "ICMP Flood (Limited)|sudo hping3 --icmp -c 20 --fast $TEST_SERVER"
        "HTTP Request Flood|for i in {1..20}; do curl -s http://$TEST_SERVER:$TEST_PORT/ & done; wait"
        "TCP Connection Flood|for i in {1..30}; do timeout 1 nc $TEST_SERVER 80 < /dev/null & done; wait"
        "Mixed Protocol Flood|sudo hping3 -S -p 80 -c 25 $TEST_SERVER & sudo hping3 --udp -p 53 -c 25 $TEST_SERVER & wait"
    )
    
    for attack in "${attacks[@]}"; do
        local name="${attack%%|*}"
        local command="${attack##*|}"
        
        echo -e "${CYAN}┌─ $name${NC}"
        echo -e "${YELLOW}│ Command: $command${NC}"
        echo -e "${RED}│ WARNING: This may cause network congestion${NC}"
        echo -e "${CYAN}└─${NC}"
        
        read -p "Execute this attack? (y/N/s=skip all): " choice
        case $choice in
            [Yy]* )
                echo -e "${GREEN}Executing...${NC}"
                eval $command
                echo
                sleep 3
                ;;
            [Ss]* )
                echo -e "${YELLOW}Skipping remaining DoS attacks${NC}"
                break
                ;;
            * )
                echo -e "${YELLOW}Skipped${NC}"
                ;;
        esac
        echo
    done
}

protocol_anomalies() {
    echo -e "${PURPLE}═══ PROTOCOL ANOMALIES ═══${NC}"
    
    local attacks=(
        "Malformed HTTP Header|printf \"GET / HTTP/1.1\\r\\nHost: $TEST_SERVER\\r\\nContent-Length: 999999999\\r\\n\\r\\n\" | nc $TEST_SERVER $TEST_PORT"
        "HTTP with Null Bytes|printf \"GET /\\x00\\x00\\x00 HTTP/1.1\\r\\nHost: $TEST_SERVER\\r\\n\\r\\n\" | nc $TEST_SERVER $TEST_PORT"
        "Oversized HTTP Method|printf \"\$(python3 -c 'print(\"A\"*1000)') / HTTP/1.1\\r\\nHost: $TEST_SERVER\\r\\n\\r\\n\" | nc $TEST_SERVER $TEST_PORT"
        "Invalid HTTP Version|printf \"GET / HTTP/9.9\\r\\nHost: $TEST_SERVER\\r\\n\\r\\n\" | nc $TEST_SERVER $TEST_PORT"
        "TCP with Invalid Flags|sudo hping3 -S -F -P -U $TEST_SERVER -p 80 -c 5"
    )
    
    for attack in "${attacks[@]}"; do
        local name="${attack%%|*}"
        local command="${attack##*|}"
        
        echo -e "${CYAN}┌─ $name${NC}"
        echo -e "${YELLOW}│ Command: $command${NC}"
        echo -e "${CYAN}└─${NC}"
        
        read -p "Execute this attack? (y/N/s=skip all): " choice
        case $choice in
            [Yy]* )
                echo -e "${GREEN}Executing...${NC}"
                eval $command
                echo
                sleep 1
                ;;
            [Ss]* )
                echo -e "${YELLOW}Skipping remaining protocol attacks${NC}"
                break
                ;;
            * )
                echo -e "${YELLOW}Skipped${NC}"
                ;;
        esac
        echo
    done
}

backdoor_attacks() {
    echo -e "${PURPLE}═══ BACKDOOR & MALWARE COMMUNICATION ═══${NC}"
    
    local attacks=(
        "Backdoor Port 1337 (Critical)|nc -zv $TEST_SERVER 1337"
        "Backdoor Port 4444 (Critical)|nc -zv $TEST_SERVER 4444"
        "Backdoor Port 31337 (Critical)|nc -zv $TEST_SERVER 31337"
        "Backdoor Port 12345 (Critical)|nc -zv $TEST_SERVER 12345"
        "Backdoor Port 6666 (Critical)|nc -zv $TEST_SERVER 6666"
        "Multiple Backdoor Ports|for port in 1337 4444 31337; do nc -zv $TEST_SERVER \$port; sleep 1; done"
        "Reverse Shell Attempt|nc -l -p 4444 & sleep 1; echo 'id; whoami; pwd' | nc $TEST_SERVER 4444"
        "Metasploit Handler Simulation|nc -zv $TEST_SERVER 4444"
        "Back Orifice Port Test|nc -u -zv $TEST_SERVER 31337"
        "Trojan Port Scan|nc -zv $TEST_SERVER 12345"
    )
    
    for attack in "${attacks[@]}"; do
        local name="${attack%%|*}"
        local command="${attack##*|}"
        
        echo -e "${CYAN}┌─ $name${NC}"
        echo -e "${YELLOW}│ Command: $command${NC}"
        echo -e "${CYAN}└─${NC}"
        
        read -p "Execute this attack? (y/N/s=skip all): " choice
        case $choice in
            [Yy]* )
                echo -e "${GREEN}Executing...${NC}"
                eval $command
                echo
                sleep 1
                ;;
            [Ss]* )
                echo -e "${YELLOW}Skipping remaining backdoor attacks${NC}"
                break
                ;;
            * )
                echo -e "${YELLOW}Skipped${NC}"
                ;;
        esac
        echo
    done
}

run_all_demo() {
    echo -e "${PURPLE}═══ RUNNING ALL ATTACK SCENARIOS ═══${NC}"
    echo -e "${RED}This will execute ALL attacks automatically with 3-second delays${NC}"
    read -p "Continue? (y/N): " confirm
    
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        return
    fi
    
    echo -e "${GREEN}Starting automated demo in 5 seconds...${NC}"
    sleep 5
    
    # Setup HTTP server first
    setup_http_server
    
    echo -e "${CYAN}Demo: Low Severity Tests${NC}"
    curl "http://$TEST_SERVER:$TEST_PORT/" &>/dev/null
    sleep 2
    curl -X OPTIONS "http://$TEST_SERVER:$TEST_PORT/" &>/dev/null
    sleep 2
    
    echo -e "${CYAN}Demo: Web Application Attacks${NC}"
    curl "http://$TEST_SERVER:$TEST_PORT/?id=1%27%20OR%201=1--" &>/dev/null
    sleep 3
    curl "http://$TEST_SERVER:$TEST_PORT/?query=SELECT%20*%20FROM%20users%20UNION%20SELECT%20username,password%20FROM%20users--" &>/dev/null
    sleep 3
    
    echo -e "${CYAN}Demo: Critical Exploits${NC}"
    curl "http://$TEST_SERVER:$TEST_PORT/?cmd=test" &>/dev/null
    sleep 2
    curl "http://$TEST_SERVER:$TEST_PORT/?exec=whoami" &>/dev/null
    sleep 2
    curl "http://$TEST_SERVER:$TEST_PORT/?file=passwd" &>/dev/null
    sleep 2
    
    echo -e "${CYAN}Demo: Network Scanning${NC}"
    sudo nmap -T4 -p 1-20 $TEST_SERVER &>/dev/null &
    sleep 5
    
    echo -e "${CYAN}Demo: Backdoor Communication${NC}"
    for port in 1337 4444 31337; do
        timeout 1 nc -zv $TEST_SERVER $port 2>/dev/null &
        sleep 1
    done
    
    echo -e "${CYAN}Demo: DoS Attack${NC}"
    sudo hping3 -S -p 80 -c 25 $TEST_SERVER &>/dev/null &
    sleep 3
    
    echo -e "${GREEN}Demo completed! Check Necronet output for detected attacks.${NC}"
}

# Main execution
main() {
    print_banner
    check_dependencies
    
    while true; do
        print_menu
        read -p "Select option: " choice
        echo
        
        case $choice in
            1) web_attacks ;;
            2) network_attacks ;;
            3) dos_attacks ;;
            4) protocol_anomalies ;;
            5) backdoor_attacks ;;
            6) run_all_demo ;;
            s|S) start_necronet ;;
            k|K) kill_necronet ;;
            h|H) setup_http_server ;;
            q|Q) 
                echo -e "${GREEN}Cleaning up...${NC}"
                kill_necronet 2>/dev/null
                pkill -f "python3 -m http.server" 2>/dev/null
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0 
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
        clear
    done
}

# Check if running as root for some commands
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}Warning: Running as root. Some commands may not work as expected.${NC}"
fi

main "$@"