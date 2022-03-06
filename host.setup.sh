sysctl -w net.ipv4.ip_local_port_range="1024 65535"
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
