#!/bin/bash

# download core
wget https://github.com/dharak36/Xray-core/releases/download/v1.0.0/xray.linux.64bit

# backup old core
mv /usr/local/etc/xray /root/xray.old

# install new core
mv /root/xray.linux.64bit /usr/local/bin/xray

# set xray permission
chmod 755 /usr/local/etc/xray

# check version
/usr/local/etc/xray version

# restart xray
reboot
