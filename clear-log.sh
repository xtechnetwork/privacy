#!/bin/bash

echo -e "\n\033[0;32mClearing...\033[0m\n"

cd /var/log || exit

sudo journalctl --vacuum-time=10d
sudo find . -type f -name "*.1" -delete
sudo find . -type f -name "*.gz" -delete
sudo find . -type f -name "*.old" -delete
sudo rm -f ./*.log.*

sudo rm -f /var/log/daemon.log
sudo rm -f /var/log/fail2ban.log 
sudo rm -f /var/log/unattended-upgrades/unattended-upgrades-dpkg.log 
sudo rm -f /var/log/unattended-upgrades/unattended-upgrades-shutdown.log 
sudo rm -f /var/log/unattended-upgrades/unattended-upgrades.log
sudo rm -f /var/log/apt/history.log 
sudo rm -f /var/log/apt/term.log 
sudo rm -f /var/log/alternatives.log 
sudo rm -f /var/log/kern.log 
sudo rm -f /var/log/bootstrap.log 
sudo rm -f /var/log/user.log clear
sudo rm -f /var/log/cloud-init-output.log 
sudo rm -f /var/log/dpkg.log 
sudo rm -f /var/log/nginx/access.log 
sudo rm -f /var/log/nginx/error.log 
sudo rm -f /var/log/nginx/vps-access.log 
sudo rm -f /var/log/nginx/vps-error.log 
sudo rm -f /var/log/cloud-init.log 
sudo rm -f /var/log/auth.log 

echo -e "\n\033[0;32mLOG Cleared!\033[0m\n"
