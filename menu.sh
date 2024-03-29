#!/bin/bash
# =========================================
# Quick Setup | Script Setup Manager
# Edition : Stable Edition V1.0
# Auther  : Xtech
# (C) Copyright 2022
# =========================================
P='\e[0;35m'
B='\033[0;36m'
G='\e[0;32m'
N='\e[0m'
export Server_URL="raw.githubusercontent.com/NevermoreSSH/XRAY/main"

clear
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
#########################
MYIP=$(wget -qO- ipv4.icanhazip.com);
clear
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
purple='\e[0;35m'
NC='\e[0m'
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'
clear
domain=$(cat /root/domain)

# // script version
myver="$(cat /home/ver)"

# // script version check
serverV=$( curl -sS https://${Server_URL}/version_check_v2)

function updatews(){
clear
echo -e "[ ${GREEN}INFO${NC} ] Check for Script updates . . ."
sleep 1
cd
wget -q -O /root/update-v2.sh "https://${Server_URL}/update-v2.sh" && chmod +x update-v2.sh && ./update-v2.sh
sleep 1
rm -f /root/update-v2.sh
rm -f /home/ver
version_check_v2=$( curl -sS https://${Server_URL}/version_check_v2)
echo "$version_check_v2" >> /home/ver
clear
echo ""
echo -e "[ ${GREEN}INFO${NC} ] Successfully Up To Date!"
sleep 1
echo ""
read -n 1 -s -r -p "Press any key to continue..."
menu
}

echo -e "\e[36m╒════════════════════════════════════════════╕\033[0m"
echo -e " \E[0;41;36m                 INFO SERVER                \E[0m"
echo -e "\e[36m╘════════════════════════════════════════════╛\033[0m"
load_cpu=$(printf '%-3s' "$(top -bn1 | awk '/Cpu/ { cpu = "" 100 - $8 "%" }; END { print cpu }')")
ram_used=$(free -m | grep Mem: | awk '{print $3}')
total_ram=$(free -m | grep Mem: | awk '{print $2}')
ram_usage=$(echo "scale=2; ($ram_used / $total_ram) * 100" | bc | cut -d. -f1)
uphours=`uptime -p | awk '{print $2,$3}' | cut -d , -f1`
upminutes=`uptime -p | awk '{print $4,$5}' | cut -d , -f1`
uptimecek=`uptime -p | awk '{print $6,$7}' | cut -d , -f1`
cekup=`uptime -p | grep -ow "day"`
IPVPS=$(curl -s icanhazip.com/ip )
daily_usage=$(vnstat -d --oneline | awk -F\; '{print $6}' | sed 's/ //')
monthly_usage=$(vnstat -m --oneline | awk -F\; '{print $11}' | sed 's/ //')
if [ "$cekup" = "day" ]; then
echo -e " System Uptime      :  $uphours $upminutes $uptimecek"
else
echo -e " System Uptime      :  $uphours $upminutes"
fi
echo -e " Memory Usage       :  ${ram_used}MB / ${total_ram}MB (${ram_usage}%)"
echo -e " CPU Load           :  $load_cpu"
echo -e " VPN Core           :  XRAY-CORE"
echo -e " Domain             :  $domain"
echo -e " IP Address         :  $IPVPS"
echo -e "\e[36m╒════════════════════════════════════════════╕\033[0m"
echo -e " [ Sys Tweak${NC} : Active ] [ AdsBlock${NC} : Active ]"
echo -e "\e[36m╘════════════════════════════════════════════╛\033[0m"
echo -e "      \033[1;37mXtech Xray Mini Script Premium\033[0m"
echo -e "\e[36m╒════════════════════════════════════════════╕\033[0m"
echo -e " Daily Data Usage   :  ${yell}$daily_usage${N}"
echo -e " Monthly Data Usage :  ${yell}$monthly_usage${N}"
echo -e "\e[36m╘════════════════════════════════════════════╛\033[0m"
echo -e "\e[36m╒════════════════════════════════════════════╕\033[0m"
echo -e " \E[0;41;36m                 XRAY MENU                  \E[0m"
echo -e "\e[36m╘════════════════════════════════════════════╛\033[0m
 [\033[1;36m•1 \033[0m]  XRAY Vless WS Panel
 [\033[1;36m•2 \033[0m]  XRAY Trojan TCP XTLS Panel"
echo -e "\e[36m╒════════════════════════════════════════════╕\033[0m"
echo -e " \E[0;41;36m                OTHERS MENU                 \E[0m"
echo -e "\e[36m╘════════════════════════════════════════════╛\033[0m
 [\033[1;36m•3 \033[0m]  Install Ads Block
 [\033[1;36m•4 \033[0m]  Ads Block Panel
 [\033[1;36m•5 \033[0m]  DNS Changer
 [\033[1;36m•6 \033[0m]  Netflix Checker"
echo -e "\e[36m╒════════════════════════════════════════════╕\033[0m"
echo -e " \E[0;41;36m                SYSTEM MENU                 \E[0m"
echo -e "\e[36m╘════════════════════════════════════════════╛\033[0m
 [\033[1;36m•7 \033[0m]  Change Domain
 [\033[1;36m•8 \033[0m]  Renew Certificate XRAY
 [\033[1;36m•9 \033[0m]  Check VPN Status
 [\033[1;36m•10\033[0m]  Check VPN Port
 [\033[1;36m•11\033[0m]  Restart VPN Services
 [\033[1;36m•12\033[0m]  Speedtest VPS
 [\033[1;36m•13\033[0m]  Check RAM
 [\033[1;36m•14\033[0m]  Check Bandwith
 [\033[1;36m•15\033[0m]  Backup
 [\033[1;36m•16\033[0m]  Restore
 [\033[1;36m•17\033[0m]  Reboot
"
if [[ $serverV > $myver ]]; then
echo -e " [\033[1;36m•24\033[0m]  Update Autoscript To V$serverV\n"
up2u="updatews"
else
up2u="menu"
fi
echo -e " \033[1;37mType [ x ] To Exit From Menu \033[0m"
echo ""
echo -e "\e[36m╒════════════════════════════════════════════╕\033[0m"
echo -e " Version       :\033[1;36m Xray Mini Lite $myver\e[0m"
echo -e " Client Name   : Xtech"
echo -e " Expiry Script : 2077-12-31"
echo -e " Status Script : ${G}Lifetime${NC}"
echo -e "\e[36m╘════════════════════════════════════════════╛\033[0m"
echo ""
echo -ne " Select menu : "; read opt
case $opt in
1) clear ; menu-vless ; read -n1 -r -p "Press any key to continue..." ; menu ;;
2) clear ; menu-xrt ; read -n1 -r -p "Press any key to continue..." ; menu ;;
3) clear ; ins-helium ; read -n1 -r -p "Press any key to continue..." ; menu ;;
4) clear ; helium ; menu ;;
5) clear ; dns ; menu ;;
6) clear ; nf ; echo "" ; menu ;;
7) clear ; add-host ; echo "" ; read -n1 -r -p "Press any key to continue..." ; menu ;;
8) clear ; certxray ; menu ;;
9) clear ; status ; menu ;;
10) clear ; port ; read -n1 -r -p "Press any key to continue..." ; menu ;;
11) clear ; restart ; read -n1 -r -p "Press any key to continue..." ; menu ;;
12) clear ; speedtest ; menu ;;
13) clear ; htop ; echo "" ; read -n1 -r -p "Press any key to continue..." ; menu ;;
14) clear ; vnstat ; echo "" ; read -n1 -r -p "Press any key to continue..." ; menu ;;
15) clear ; backup ; echo "" ; read -n1 -r -p "Press any key to continue..." ; menu ;;
16) clear ; restore ; read -n1 -r -p "Press any key to continue..." ; menu ;;
17) clear ; reboot ; menu ;;
18) clear ; $up2u ; read -n1 -r -p "Press any key to continue..." ; menu ;;
00 | 0) clear ; menu ;;
x | X) exit ;;
*) clear ; menu ;;
esac
