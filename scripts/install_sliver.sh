#!/bin/bash

# OBLITERATUS - Command & Control Synthesis
# Objective: Deployment of the Sliver C2 Framework (Adversary Emulation)

echo "[*] Initializing Sliver C2 Deployment..."

# Dependency Resolution
sudo apt-get update
sudo apt-get install -y mingw-w64 binutils-mingw-w64 g++-mingw-w64

# Retrieval of the Sliver Binary (Release version)
SLIVER_URL="https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux"
curl -L $SLIVER_URL -o sliver-server
chmod +x sliver-server

echo "[+] Sliver Server deployed. Execution command: ./sliver-server"

# Note: For complete Signal Integrity, it is recommended to run 
# the server behind a secure redirector or within a controlled environment.
