#!/bin/bash

echo -e "\n\033[0;32mClearing...\033[0m\n"

cd /var/log || exit

sudo journalctl --vacuum-time=10d
sudo find . -type f -name "*.1" -delete
sudo find . -type f -name "*.gz" -delete
sudo find . -type f -name "*.old" -delete
sudo rm -f ./*.log.*

echo -e "\n\033[0;32mLOG Cleared!\033[0m\n"
