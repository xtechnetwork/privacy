#!/bin/bash

# Initialize variables
PURPLE='\033[0;35m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
repoDir='https://raw.githubusercontent.com/iriszz-official/ubuntu/main/'
netInt=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1)

# Check services
checkRun() {
	if [[ "$(systemctl is-active $1)" == "active" ]]; then
		echo -e "${GREEN}Service '$1' is running.${NC}"
		sleep 1
	else
		echo -e "${RED}Service '$1' is not running.${NC}\n"
		exit 1
	fi
}
checkScreen() {
	if screen -ls | grep -qw $1; then
		echo -e "${GREEN}Service '$1' is running.${NC}"
		sleep 1
	else
		echo -e "${RED}Service '$1' is not running.${NC}\n"
		exit 1
	fi
}
checkInstall() {
	if [[ 0 -eq $? ]]; then
		echo -e "${GREEN}Package '$1' is installed.${NC}"
		sleep 1
	else
		echo -e "${RED}Package '$1' is not installed.${NC}\n"
		exit 1
	fi
}

clear

# Check environment
function os_check() {
	source '/etc/os-release'
	if [[ "${ID}" != "ubuntu" && $(echo "${VERSION_ID}") != "20.04" ]]; then
		echo -e "${RED}This script is only for Ubuntu 20.04.${NC}\n"
		exit 1
	fi
}
echo -e "${PURPLE}[+] Checking environment ...${NC}"
sleep 1
if [[ $EUID -ne 0 ]]; then
	echo -e "${RED}This script must be run as root!${NC}\n"
	exit 1
fi
apt update > /dev/null 2>&1
apt install -y virt-what > /dev/null 2>&1
if ! [[ "$(virt-what)" == "kvm" || "$(virt-what)" == "hyperv" ]]; then
	echo -e "${RED}This script is only for KVM virtualization.${NC}\n"
	exit 1
fi
os_check

# Update packages
echo -e "${PURPLE}[+] Updating packages ...${NC}"
sleep 1
apt update > /dev/null 2>&1
apt upgrade -y > /dev/null 2>&1
apt autoremove -y > /dev/null 2>&1

# Install script dependencies
echo -e "${PURPLE}[+] Installing script dependencies ...${NC}"
apt install -y systemd curl wget curl screen cmake zip unzip vnstat tar openssl git uuid-runtime > /dev/null 2>&1
checkInstall "systemd curl wget curl screen cmake unzip vnstat tar openssl git uuid-runtime"

# Get domain
echo -e ""
read -p "Enter your domain name (www.voidvpn.top) : " domain
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
ip=$(wget -qO- ipv4.icanhazip.com)
echo -e "${PURPLE}\n[+] Checking domain name ...${NC}"
sleep 1
if [[ ${domain_ip} == "${ip}" ]]; then
	echo -e "${GREEN}IP matched with the server.${NC}"
	sleep 1
elif grep -qw "$domain" /etc/hosts; then
	echo -e "${GREEN}IP matched with hostname.${NC}"
else
	echo -e "${RED}IP does not match with the server. Make sure to point A record to your server.${NC}\n"
	exit 1
fi

# Optimize settings
echo -e "${PURPLE}[+] Optimizing settings ...${NC}"
sleep 1
locale-gen en_US > /dev/null 2>&1

# Change timezone
echo -e "${PURPLE}[+] Changing timezone to Asia/Kuala_Lumpur (GMT +8) ...${NC}"
sleep 1
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# Disable IPv6
echo -e "${PURPLE}[+] Disabling IPv6 ...${NC}"
sleep 1
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1 > /dev/null 2>&1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

# Enable BBR
echo -e "${PURPLE}[+] Enabling BBR ...${NC}"
sleep 1
sysctl -w net.core.default_qdisc=fq > /dev/null 2>&1
sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1
echo -e "net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

# Reset iptables
echo -e "${PURPLE}[+] Resetting iptables ...${NC}"
sleep 1
apt install -y iptables-persistent
checkInstall iptables-persistent
ufw disable > /dev/null 2>&1
iptables-save | awk '/^[*]/ { print $1 } 
                     /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                     /COMMIT/ { print $0; }' | iptables-restore

# Configure Cron
if [ $(dpkg-query -W -f='${Status}' cron 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
	echo -e "${PURPLE}[+] Installing cron ...${NC}"
	sleep 1
	apt install -y cron > /dev/null 2>&1
	checkInstall cron
fi
echo -e "${PURPLE}[+] Configuring cron ...${NC}"
sleep 1
mkdir /voidvpn
wget -O /voidvpn/cron.daily "${repoDir}files/cron.daily" > /dev/null 2>&1
chmod +x /voidvpn/cron.daily

# Configure SSH
echo -e "${PURPLE}[+] Configuring SSH ...${NC}"
sleep 1

# Install Dropbear
echo -e "${PURPLE}[+] Installing Dropbear ...${NC}"
sleep 1

echo -e "${PURPLE}[+] Configuring Dropbear ...${NC}"
sleep 1

# Install Stunnel
echo -e "${PURPLE}[+] Installing Stunnel ...${NC}"
sleep 1

echo -e "${PURPLE}[+] Configuring Stunnel ...${NC}"
sleep 1

# Install OpenVPN
echo -e "${PURPLE}[+] Installing OpenVPN ...${NC}"
sleep 1

echo -e "${PURPLE}[+] Configuring OpenVPN ...${NC}"
sleep 1

# Configure OpenVPN client configuration
echo -e "${PURPLE}[+] Configuring OpenVPN configuration ...${NC}"
sleep 1

# Install Squid
echo -e "${PURPLE}[+] Installing Squid ...${NC}"
sleep 1

# Install Open HTTP Puncher
echo -e "${PURPLE}[+] Installing OHP ...${NC}"
sleep 1

# Install BadVPN UDPGw
echo -e "${PURPLE}[+] Installing BadVPN UDPGw ...${NC}"
sleep 1

# Install Xray
echo -e "${PURPLE}[+] Installing Xray ...${NC}"
sleep 1
rm -f /etc/apt/sources.list.d/nginx.list
apt install -y lsb-release gnupg2 > /dev/null 2>&1
checkInstall lsb-release gnupg2
echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add - > /dev/null 2>&1
apt update > /dev/null 2>&1
apt install -y lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq > /dev/null 2>&1
checkInstall "lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq"
mkdir -p /usr/local/bin
curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install > /dev/null 2>&1
checkInstall xray
echo $domain > /usr/local/etc/xray/domain
wget -O /usr/local/etc/xray/xtls.json "${repoDir}files/xray/xray_xtls.json" > /dev/null 2>&1
wget -O /usr/local/etc/xray/ws.json "${repoDir}files/xray/xray_ws.json" > /dev/null 2>&1
sed -i "s/xx/${domain}/g" /usr/local/etc/xray/ws.json
echo -e "${PURPLE}[+] Installing Nginx ...${NC}"
sleep 1
if ! command -v nginx > /dev/null 2>&1; then
	apt install -y nginx > /dev/null 2>&1
fi
checkInstall nginx
echo -e "${PURPLE}[+] Configuring Nginx ...${NC}"
sleep 1
rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d
wget -O /etc/nginx/conf.d/${domain}.conf "${repoDir}files/xray/web.conf" > /dev/null 2>&1
sed -i "s/xx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
nginxConfig=$(systemctl status nginx | grep loaded | awk '{print $3}' | tr -d "(;")
sed -i "/^ExecStart=.*/i ExecStartPost=/bin/sleep 0.1" $nginxConfig
systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx > /dev/null 2>&1
rm -rf /var/www/html
mkdir -p /var/www/html
wget -O web.tar.gz "${repoDir}files/web.tar.gz" > /dev/null 2>&1
tar xzf web.tar.gz -C /var/www/html > /dev/null 2>&1
nginxUser=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $2}')
nginxGroup=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $3}')
chown -R ${nginxUser}:${nginxGroup} /var/www/html
find /var/www/html/ -type d -exec chmod 750 {} \;
find /var/www/html/ -type f -exec chmod 640 {} \;
rm -f web.tar.gz
echo -e "${PURPLE}[+] Configuring Xray ...${NC}"
sleep 1
signedcert=$(xray tls cert -domain="$domain" -name="Iriszz" -org="Void VPN" -expire=87600h)
echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee /usr/local/etc/xray/self_signed_cert.pem > /dev/null 2>&1
echo $signedcert | jq '.key[]' | sed 's/\"//g' > /usr/local/etc/xray/self_signed_key.pem
openssl x509 -in /usr/local/etc/xray/self_signed_cert.pem -noout
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_cert.pem
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_key.pem
mkdir /voidvpn/xray
touch /voidvpn/xray/xray-clients.txt
curl -sL https://get.acme.sh | bash > /dev/null 2>&1
"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt > /dev/null 2>&1
systemctl restart nginx
if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/var/www/html" -k ec-256 --force > /dev/null 2>&1; then
	echo -e "SSL certificate generated."
	sleep 1
	if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /voidvpn/xray/xray.crt --keypath /voidvpn/xray/xray.key --reloadcmd "systemctl restart xray@xtls" --ecc --force > /dev/null 2>&1; then
		echo -e "SSL certificate installed."
		sleep 1
	fi
else
	echo -e "${RED}Error installing/configuring SSL certificate.${NC}\n"
	exit 1
fi
chown -R nobody.nogroup /voidvpn/xray/xray.crt
chown -R nobody.nogroup /voidvpn/xray/xray.key
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@xtls
systemctl restart xray@ws
systemctl enable xray@xtls > /dev/null 2>&1
systemctl enable xray@ws > /dev/null 2>&1
checkRun nginx
checkRun xray@xtls
checkRun xray@ws

# Install WireGuard
echo -e "${PURPLE}[+] Installing WireGuard ...${NC}"
sleep 1

# Install Speedtest CLI
echo -e "${PURPLE}[+] Installing Speedtest CLI ...${NC}"
sleep 1

# Install fail2ban
echo -e "${PURPLE}[+] Installing Fail2Ban ...${NC}"
sleep 1
apt install -y fail2ban > /dev/null 2>&1
checkInstall fail2ban
systemctl restart fail2ban
checkRun fail2ban

# Install DDoS Deflate
echo -e "${PURPLE}[+] Installing DDoS Deflate ...${NC}"
sleep 1
apt install -y dnsutils tcpdump dsniff grepcidr net-tools > /dev/null 2>&1
checkInstall "dnsutils tcpdump dsniff grepcidr net-tools"
wget -O ddos.zip "${repoDir}files/ddos-deflate.zip" > /dev/null 2>&1
unzip ddos.zip > /dev/null 2>&1
cd ddos-deflate
chmod +x install.sh
./install.sh > /dev/null 2>&1
cd
rm -rf ddos.zip ddos-deflate
checkRun ddos

# Configure rc.local
echo -e "${PURPLE}[+] Checking for rc.local service ...${NC}"
sleep 1
systemctl status rc-local > /dev/null 2>&1
if [[ 0 -ne $? ]]; then
	echo -e "${PURPLE}[+] rc.local is not installed, installing rc.local ...${NC}"
	sleep 1
	wget -O /etc/systemd/system/rc-local.service "${repoDir}files/rc-local.service" > /dev/null 2>&1
	echo -e "${PURPLE}[+] Configuring rc.local ...${NC}"
	sleep 1
	wget -O /etc/rc.local "${repoDir}files/rc.local" > /dev/null 2>&1
	chmod +x /etc/rc.local
	systemctl start rc-local
	systemctl enable rc-local > /dev/null 2>&1
	checkRun rc-local
else
	echo -e "${PURPLE}[+] rc.local is enabled, configuring rc.local ...${NC}"
	sleep 1
	wget -O /etc/rc.local "${repoDir}files/rc.local" > /dev/null 2>&1
	systemctl start rc-local
	systemctl enable rc-local > /dev/null 2>&1
	checkRun rc-local
fi

# Block Torrent (iptables)
echo -e "${PURPLE}[+] Configuring iptables to block Torrent ...${NC}"
sleep 1
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# Save iptables
echo -e "${PURPLE}[+] Saving iptables ...${NC}"
sleep 1
iptables-save > /voidvpn/iptables.rules

# Configure Google Drive backup
echo -e "${PURPLE}[+] Configuring Google Drive backup ...${NC}"
sleep 1

# Configure menu
echo -e "${PURPLE}[+] Configuring menu ...${NC}"
sleep 1
wget -O /usr/bin/menu "${repoDir}files/menu/menu.sh" > /dev/null 2>&1
wget -O /usr/bin/xray-script "${repoDir}files/menu/xray-script.sh" > /dev/null 2>&1
wget -O /usr/bin/check-script "${repoDir}files/menu/check-script.sh" > /dev/null 2>&1
chmod +x /usr/bin/{menu,ssh-vpn-script,xray-script,wireguard-script,check-script,backup-script}

# Cleanup and reboot
rm -f /root/install.sh
cat /dev/null > ~/.bash_history
echo -e "clear
cat /dev/null > ~/.bash_history
history -c" >> ~/.bash_logout
echo -e ""
echo -e "${GREEN}Script executed succesfully.${NC}"
echo -e ""
read -n 1 -r -s -p $"Press enter to reboot >> "
echo -e "\n"
reboot
