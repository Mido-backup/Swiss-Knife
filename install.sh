#!/bin/bash

# Define colors for stylish output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display a stylish header
header() {
    clear
    echo -e "${YELLOW}Swiss Knife Cybersecurity Toolkit${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install dependencies
install_dependencies() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    if command_exists apt-get; then
        sudo apt-get update -y >/dev/null 2>&1
        sudo apt-get install -y python3 python3-pip >/dev/null 2>&1
    elif command_exists yum; then
        sudo yum install -y python3 python3-pip >/dev/null 2>&1
    elif command_exists brew; then
        brew install python3 >/dev/null 2>&1
    else
        echo -e "${RED}[!] Unsupported package manager. Please install Python 3 and pip manually.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Dependencies installed successfully!${NC}"
}

# Function to install Python requirements
install_python_requirements() {
    echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
    pip3 install nmap scapy requests beautifulsoup4 colorama pynput whois cryptography dnspython --break-system-packages >/dev/null 2>&1
    echo -e "${GREEN}[+] Python dependencies installed successfully!${NC}"
}

# Function to make the toolkit executable
make_executable() {
    echo -e "${YELLOW}[*] Making swissknife.py executable...${NC}"
    chmod +x swissknife.py
    echo -e "${GREEN}[+] swissknife.py is now executable!${NC}"
}

# Function to create a symlink for easy access
create_symlink() {
    echo -e "${YELLOW}[*] Creating symlink for easy access...${NC}"
    sudo ln -sf "$(pwd)/swissknife.py" /usr/local/bin/swissy
    echo -e "${GREEN}[+] Symlink created! You can now run 'swissy' from anywhere.${NC}"
}

# Main installation function
main() {
    header
    echo -e "${YELLOW}[*] Starting installation of Swiss Army Knife Cybersecurity Toolkit...${NC}"

    # Install dependencies
    install_dependencies

    # Install Python requirements
    install_python_requirements

    # Make swissknife.py executable
    make_executable

    # Create symlink
    create_symlink

    echo -e "${GREEN}[+] Installation complete!${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${YELLOW}To start the toolkit, simply type 'swissy' in your terminal.${NC}"
    echo
}

# Run the main function
main
