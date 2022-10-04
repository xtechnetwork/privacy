#!/bin/bash

# Color
N="\033[0m"
BD="\033[1m"
R="\033[0;31m"
G="\033[0;32m"
B="\033[0;34m"
Y="\033[0;33m"
C="\033[0;36m"
P="\033[0;35m"
LR="\033[1;31m"
LG="\033[1;32m"
LB="\033[1;34m"
RB="\033[41;37m"
GB="\033[42;37m"
BB="\033[44;37m"

# Notification
OK="[ ${LG}OK${N} ]"
ERROR="[ ${LR}ERROR${N} ]"
INFO="[ ${C}INFO${N} ]"

# Source
repo="https://raw.githubusercontent.com/skynetcenter/ubuntu-vpn/main/"

# Check Services
check_run() {
	if [[ "$(systemctl is-active $1)" == "active" ]]; then
		echo -e "${OK} Service $1 is running${N}"
		sleep 1
	else
		echo -e "${ERROR} Service $1 is not running${N}\n"
		exit 1
	fi
}
check_screen() {
	if screen -ls | grep -qw $1; then
		echo -e "${OK} Service $1 is running${N}"
		sleep 1
	else
		echo -e "${ERROR} Service $1 is not running${N}\n"
		exit 1
	fi
}
check_install() {
	if [[ 0 -eq $? ]]; then
		echo -e "${OK} Package $1 is installed${N}"
		sleep 1
	else
		echo -e "${ERROR} Package $1 is not installed${N}\n"
		exit 1
	fi
}

clear

# Check Environment
os_check() {
	source '/etc/os-release'
	if [[ "${ID}" != "ubuntu" && $(echo "${VERSION_ID}") != "20.04" ]]; then
		echo -e "${ERROR} Autoscript only supported on Ubuntu 20.04${N}\n"
		exit 1
	fi
}
echo -e "${INFO} ${B}Checking environment ...${N}"
sleep 1
if [[ $EUID -ne 0 ]]; then
	echo -e "${ERROR} Autoscript must be run as root${N}\n"
	exit 1
fi
apt update > /dev/null 2>&1
apt install -y virt-what > /dev/null 2>&1
if ! [[ "$(virt-what)" == "kvm" || "$(virt-what)" == "hyperv" ]]; then
	echo -e "${ERROR} Autoscript only supported on KVM virtualization${N}\n"
	exit 1
fi
os_check

# Update Packages
echo -e "${INFO} ${B}Updating packages ...${N}"
sleep 1
apt update > /dev/null 2>&1
apt upgrade -y > /dev/null 2>&1
apt autoremove -y > /dev/null 2>&1

# Install Dependencies
echo -e "${INFO} ${B}Installing autoscript dependencies ...${N}"
apt install -y systemd curl wget screen cmake zip unzip vnstat tar openssl git uuid-runtime > /dev/null 2>&1
check_install "systemd curl wget screen cmake unzip vnstat tar openssl git uuid-runtime"

# Get Domain
echo -e ""
read -p "Enter a valid domain name : " domain
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
ip=$(wget -qO- ipv4.icanhazip.com)
echo -e ""
echo -e "${INFO} ${B}Checking domain name ...${N}"
sleep 1
if [[ ${domain_ip} == "${ip}" ]]; then
	echo -e "${OK} IP matched with the server${N}"
	sleep 1
elif grep -qw "$domain" /etc/hosts; then
	echo -e "${OK} IP matched with hostname${N}"
else
	echo -e "${ERROR} IP does not match with the server${N}\n"
	exit 1
fi

# Optimize Settings
echo -e "${INFO} ${B}Optimizing settings ...${N}"
sleep 1
sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
echo -e "* soft nofile 65536
* hard nofile 65536" >> /etc/security/limits.conf
locale-gen en_US > /dev/null 2>&1

# Set Timezone
echo -e "${INFO} ${B}Set timezone Asia/Kuala_Lumpur GMT +08 ...${N}"
sleep 1
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime
systemctl start systemd-timesyncd
date

# Disable IPv6
echo -e "${INFO} ${B}Disabling IPv6 ...${N}"
sleep 1
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1 > /dev/null 2>&1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

# Enable BBR
echo -e "Select congestion control or press enter to select default"
echo -e " [1] BBR (default)"
echo -e " [2] BBRPlus"
echo -e "Select: \c"
read tcp
case $tcp in
1)
  tcp="bbr"
  ;;
2)
  tcp="bbrplus"
  ;;
*)
  tcp="bbr"
  ;;
esac
echo -e "Select queue algorithm or press enter to select default"
echo -e " [1] FQ (default)"
echo -e " [2] FQ-Codel"
echo -e " [3] FQ-PIE"
echo -e " [4] Cake"
echo -e "Select: \c"
read queue
case $queue in
1)
  queue="fq"
  ;;
2)
  queue="fq_codel"
  ;;
3)
  queue="fq_pie"
  ;;
4)
  queue="cake"
  ;;
*)
  queue="fq"
  ;;
esac
echo -e "Enable ECN or press enter to select default"
echo -e " [1] OFF (default)"
echo -e " [2] ON"
echo -e " [3] Inbound request only"
echo -e "Select: \c"
read ecn
case $ecn in
1)
  ecn="0"
  ;;
2)
  ecn="1"
  ;;
3)
  ecn="2"
  ;;
*)
  ecn="0"
  ;;
esac
echo -e "${INFO} ${B}Enabling ${tcp} + ${queue} ...${N}"
sleep 1
sysctl -w net.ipv4.tcp_congestion_control=$tcp > /dev/null 2>&1
echo "net.ipv4.tcp_congestion_control = $tcp" >> /etc/sysctl.conf
sysctl -w net.core.default_qdisc=$queue > /dev/null 2>&1
echo "net.core.default_qdisc = $queue" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_ecn=$ecn > /dev/null 2>&1
echo "net.ipv4.tcp_ecn = $ecn" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

# Reset Iptables
echo -e "${INFO} ${B}Resetting Iptables ...${N}"
sleep 1
apt install -y iptables-persistent > /dev/null 2>&1
check_install iptables-persistent
ufw disable > /dev/null 2>&1
iptables-save | awk '/^[*]/ { print $1 } 
                     /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                     /COMMIT/ { print $0; }' | iptables-restore

# Configure Cron
if [ $(dpkg-query -W -f='${Status}' cron 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
	echo -e "${INFO} ${B}Installing Cron ...${N}"
	sleep 1
	apt install -y cron > /dev/null 2>&1
	check_install cron
fi
echo -e "${INFO} ${B}Configuring Cron ...${N}"
sleep 1
mkdir /metavpn
wget -O /metavpn/cron.daily "${repo}files/cron.daily" > /dev/null 2>&1
chmod +x /metavpn/cron.daily
(crontab -l; echo "0 6 * * * /metavpn/cron.daily") | crontab -

# Configure SSH
echo -e "${INFO} ${B}Configuring SSH ...${N}"
sleep 1
echo "" > /etc/issue.net
echo "       ▒█▀▄▀█ ▒█▀▀▀ ▀▀█▀▀ ░█▀▀█ ▒█░░▒█ ▒█▀▀█ ▒█▄░▒█" >> /etc/issue.net
echo "       ▒█▒█▒█ ▒█▀▀▀ ░▒█░░ ▒█▄▄█ ░▒█▒█░ ▒█▄▄█ ▒█▒█▒█" >> /etc/issue.net
echo "       ▒█░░▒█ ▒█▄▄▄ ░▒█░░ ▒█░▒█ ░░▀▄▀░ ▒█░░░ ▒█░░▀█" >> /etc/issue.net
echo "       ==========A C C E S S  S E R V E R==========" >> /etc/issue.net
echo "" >> /etc/issue.net
sed -i "s/#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config
mkdir /metavpn/ssh
touch /metavpn/ssh/ssh-clients.txt
systemctl restart ssh
check_run ssh

# Install Dropbear
echo -e "${INFO} ${B}Installing Dropbear ...${N}"
sleep 1
echo -e "${INFO} ${B}Configuring Dropbear ...${N}"
sleep 1

# Install Stunnel
echo -e "${INFO} ${B}Installing Stunnel ...${N}"
sleep 1
echo -e "${INFO} ${B}Configuring Stunnel ...${N}"
sleep 1

# Install OpenVPN
echo -e "${INFO} ${B}Installing OpenVPN ...${N}"
sleep 1
echo -e "${INFO} ${B}Configuring OpenVPN ...${N}"
sleep 1

# Configure OpenVPN Client
echo -e "${INFO} ${B}Configuring OpenVPN client ...${N}"
sleep 1

# Install Squid
echo -e "${INFO} ${B}Installing Squid ...${N}"
sleep 1

# Install Open HTTP Puncher
echo -e "${INFO} ${B}Installing OHP server ...${N}"
sleep 1

# Install BadVPN UDPGW
echo -e "${INFO} ${B}Installing BadVPN UDPGW ...${N}"
sleep 1

# Install Xray
echo -e "${INFO} ${B}Installing Xray ...${N}"
sleep 1
rm -f /etc/apt/sources.list.d/nginx.list
apt install -y lsb-release gnupg2 > /dev/null 2>&1
check_install lsb-release gnupg2
echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add - > /dev/null 2>&1
apt update > /dev/null 2>&1
apt install -y lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq > /dev/null 2>&1
check_install "lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq"
mkdir -p /usr/local/bin
curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install > /dev/null 2>&1
check_install xray
echo $domain > /usr/local/etc/xray/domain
wget -O /usr/local/etc/xray/xtls.json "${repo}files/xray/xray_xtls.json" > /dev/null 2>&1
wget -O /usr/local/etc/xray/ws.json "${repo}files/xray/xray_ws.json" > /dev/null 2>&1
sed -i "s/xx/${domain}/g" /usr/local/etc/xray/ws.json
echo -e "${INFO} ${B}Installing Nginx ...${N}"
sleep 1
if ! command -v nginx > /dev/null 2>&1; then
	apt install -y nginx > /dev/null 2>&1
fi
check_install nginx
echo -e "${INFO} ${B}Configuring Nginx ...${N}"
sleep 1
rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d
wget -O /etc/nginx/conf.d/${domain}.conf "${repo}files/xray/web.conf" > /dev/null 2>&1
sed -i "s/xx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
nginxConfig=$(systemctl status nginx | grep loaded | awk '{print $3}' | tr -d "(;")
sed -i "/^ExecStart=.*/i ExecStartPost=/bin/sleep 0.1" $nginxConfig
systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx > /dev/null 2>&1
rm -rf /var/www/html
mkdir -p /var/www/html/css
wget -O /var/www/html/index.html "${repo}files/web/index.html" > /dev/null 2>&1
wget -O /var/www/html/css/style.css "${repo}files/web/style.css" > /dev/null 2>&1
nginxUser=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $2}')
nginxGroup=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $3}')
chown -R ${nginxUser}:${nginxGroup} /var/www/html
find /var/www/html/ -type d -exec chmod 750 {} \;
find /var/www/html/ -type f -exec chmod 640 {} \;
echo -e "${INFO} ${B}Configuring Xray ...${N}"
sleep 1
signedcert=$(xray tls cert -domain="$domain" -name="Meta VPN" -org="Upcloud Ltd" -expire=87600h)
echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee /usr/local/etc/xray/self_signed_cert.pem > /dev/null 2>&1
echo $signedcert | jq '.key[]' | sed 's/\"//g' > /usr/local/etc/xray/self_signed_key.pem
openssl x509 -in /usr/local/etc/xray/self_signed_cert.pem -noout
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_cert.pem
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_key.pem
mkdir /metavpn/xray
touch /metavpn/xray/xray-clients.txt
curl -sL https://get.acme.sh | bash > /dev/null 2>&1
"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt > /dev/null 2>&1
systemctl restart nginx
if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/var/www/html" -k ec-256 --force > /dev/null 2>&1; then
	echo -e "SSL certificate generated"
	sleep 1
	if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /metavpn/xray/xray.crt --keypath /metavpn/xray/xray.key --reloadcmd "systemctl restart xray@xtls" --ecc --force > /dev/null 2>&1; then
		echo -e "SSL certificate installed"
		sleep 1
	fi
else
	echo -e "${ERROR} Invalid installing and configuring SSL certificate${N}\n"
	exit 1
fi
chown -R nobody.nogroup /metavpn/xray/xray.crt
chown -R nobody.nogroup /metavpn/xray/xray.key
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@xtls
systemctl restart xray@ws
systemctl enable xray@xtls > /dev/null 2>&1
systemctl enable xray@ws > /dev/null 2>&1
check_run nginx
check_run xray@xtls
check_run xray@ws

# Install WireGuard
echo -e "${INFO} ${B}Installing WireGuard ...${N}"
sleep 1

# Install Speedtest CLI
echo -e "${INFO} ${B}Installing Speedtest CLI ...${N}"
sleep 1

# Install Fail2Ban
echo -e "${INFO} ${B}Installing Fail2Ban ...${N}"
sleep 1
apt install -y fail2ban > /dev/null 2>&1
check_install fail2ban
systemctl restart fail2ban
check_run fail2ban

# Install DDOS Deflate
echo -e "${INFO} ${B}Installing DDOS Deflate ...${N}"
sleep 1
apt install -y dnsutils tcpdump dsniff grepcidr net-tools > /dev/null 2>&1
check_install "dnsutils tcpdump dsniff grepcidr net-tools"
wget -O ddos.zip "${repo}files/ddos-deflate.zip" > /dev/null 2>&1
unzip ddos.zip > /dev/null 2>&1
cd ddos-deflate
chmod +x install.sh
./install.sh > /dev/null 2>&1
cd
rm -rf ddos.zip ddos-deflate
check_run ddos

# Configure rc.local
echo -e "${INFO} ${B}Checking for rc.local service ...${N}"
sleep 1
systemctl status rc-local > /dev/null 2>&1
if [[ 0 -ne $? ]]; then
	echo -e "${INFO} ${B}Installing rc.local ...${N}"
	sleep 1
	wget -O /etc/systemd/system/rc-local.service "${repo}files/rc-local.service" > /dev/null 2>&1
	echo -e "${INFO} ${B}Configuring rc.local ...${N}"
	sleep 1
	wget -O /etc/rc.local "${repo}files/rc.local" > /dev/null 2>&1
	chmod +x /etc/rc.local
	systemctl start rc-local
	systemctl enable rc-local > /dev/null 2>&1
	check_run rc-local
else
	echo -e "${INFO} ${B}Configuring rc.local ...${N}"
	sleep 1
	wget -O /etc/rc.local "${repo}files/rc.local" > /dev/null 2>&1
	systemctl start rc-local
	systemctl enable rc-local > /dev/null 2>&1
	check_run rc-local
fi

# Save Iptables
echo -e "${INFO} ${B}Saving Iptables ...${N}"
sleep 1
iptables-save > /metavpn/iptables.rules

# Configure Menu
echo -e "${INFO} ${B}Configuring menu ...${N}"
sleep 1
wget -O /usr/bin/menu "${repo}files/menu/menu.sh" > /dev/null 2>&1
wget -O /usr/bin/ssh-vpn-script "${repo}files/menu/ssh-vpn-script.sh" > /dev/null 2>&1
wget -O /usr/bin/xray-script "${repo}files/menu/xray-script.sh" > /dev/null 2>&1
wget -O /usr/bin/wireguard-script "${repo}files/menu/wireguard-script.sh" > /dev/null 2>&1
wget -O /usr/bin/check-script "${repo}files/menu/check-script.sh" > /dev/null 2>&1
wget -O /usr/bin/nench-script "${repo}files/menu/nench-script.sh" > /dev/null 2>&1
wget -O /usr/bin/stream-script "${repo}files/menu/stream-script.sh" > /dev/null 2>&1
chmod +x /usr/bin/{menu,ssh-vpn-script,xray-script,wireguard-script,check-script,nench-script,stream-script}

# Reboot
rm -f /root/autoscript.sh
cat /dev/null > ~/.bash_history
echo -e "clear
cat /dev/null > ~/.bash_history
history -c" >> ~/.bash_logout
echo -e ""
echo -e "${OK} Autoscript installation completed${N}"
echo -e ""
read -n 1 -r -s -p "Press enter to reboot"
echo -e "\n"
reboot
