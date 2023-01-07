sudo apt install -y iptables-persistent
sudo apt autoremove --purge ufw -y

rm -f /etc/iptables/rules.v4
cat> /etc/iptables/rules.v4 << V4
# Generated by xtables-save v1.8.2 on Sun Oct  2 12:32:04 2022
*filter
:INPUT ACCEPT [97:4296]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [1170:180238]
:f2b-sshd - [0:0]
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp --dport 22  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 443  -m state --state NEW -j ACCEPT
-A FORWARD -m string --string "get_peers" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "announce_peer" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "find_node" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "BitTorrent" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "BitTorrent protocol" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "peer_id=" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string ".torrent" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "announce.php?passkey=" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "torrent" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "announce" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "info_hash" --algo bm --to 65535 -j DROP
-A f2b-sshd -s 61.177.172.19/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 83.16.184.66/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 103.200.20.19/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 61.177.172.90/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 89.22.67.66/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 61.177.173.53/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 61.177.173.47/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 31.47.192.98/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 45.95.235.42/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 14.204.145.108/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 61.177.172.140/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 99.37.212.75/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 134.17.16.5/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 104.236.72.182/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 128.199.238.70/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 92.50.249.166/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 157.245.140.49/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 219.65.68.153/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -j RETURN
COMMIT
V4
iptables-restore -t < /etc/iptables/rules.v4

rm -f /etc/iptables.up.rules
cat> /etc/iptables.up.rules << RULES
# Generated by xtables-save v1.8.2 on Sun Oct  2 12:32:04 2022
*filter
:INPUT ACCEPT [97:4296]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [1170:180238]
:f2b-sshd - [0:0]
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp --dport 22  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 443  -m state --state NEW -j ACCEPT
-A FORWARD -m string --string "get_peers" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "announce_peer" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "find_node" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "BitTorrent" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "BitTorrent protocol" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "peer_id=" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string ".torrent" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "announce.php?passkey=" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "torrent" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "announce" --algo bm --to 65535 -j DROP
-A FORWARD -m string --string "info_hash" --algo bm --to 65535 -j DROP
-A f2b-sshd -s 61.177.172.19/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 83.16.184.66/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 103.200.20.19/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 61.177.172.90/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 89.22.67.66/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 61.177.173.53/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 61.177.173.47/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 31.47.192.98/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 45.95.235.42/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 14.204.145.108/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 61.177.172.140/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 99.37.212.75/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 134.17.16.5/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 104.236.72.182/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 128.199.238.70/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 92.50.249.166/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 157.245.140.49/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 219.65.68.153/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -j RETURN
COMMIT
RULES
iptables-restore -t < /etc/iptables.up.rules

rm -rf ip2l.sh
sudo reboot 