```# Flush rules and delete custom chains
iptables -F
iptables -X

# Define chain to allow particular inbound
iptables -N chain-inbound-rules
iptables -A chain-inbound-rules -p tcp --dport 80 -j ACCEPT
iptables -A chain-inbound-rules -p tcp --dport 22 -j ACCEPT

# Define chain to allow particular outbound
iptables -N chain-outbound-rules
iptables -A chain-outbound-rules -j ACCEPT

# Define chain to allow established connections
iptables -N chain-states
iptables -A chain-states -p tcp  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A chain-states -p udp  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A chain-states -p icmp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A chain-states -j RETURN

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Accept everything on loopback
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Accept incoming/outgoing packets for established connections
iptables -A INPUT  -j chain-states
iptables -A OUTPUT -j chain-states

# Accept incoming ICMP
iptables -A INPUT -p icmp -j ACCEPT

# Accept inbound rules
iptables -A INPUT -j chain-inbound-rules

# Accept outbound rules
iptables -A OUTPUT -j chain-outbound-rules

## Drop everything else
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  DROP```