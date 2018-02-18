# arpreply

A tool to politely respond to ARP requests.

This tool is not intended to perform ARP poisoning. It waits for ARP requests for
a given IP address and reply with the specified MAC address. This comes handy in
different situations, see examples below.

## Use case: Pc with multiple addresses on the same local network range

With linux we cannot assign two IP addresses belonging to the same network range
to multiple interfaces on the same host as it makes routing to that network
ambiguous as the system does not know which interface to use to deliver a packet
to that network.

We can use this tool to easily provide an additional IP address to the host to
receive packets destinated to it.

## Use case: Forward connections to remote L3 VPN client

Supposing we have a VPN server (10.0.0.1) on a local network 192.168.1.0/24 and we are connecting
to it remotely with our client whose ip on the VPN is 10.0.0.2.

We want the clients on the network 192.168.1.0/24 to reach our 10.0.0.2 client.
Traditionally we would need to setup a VPN server in L2 bridge mode, but this
is a complicate setup and it requires changing the VPN server interfaces configuration.
We can achieve the same effect on a L3 VPN server with this tool.

Supposing that we want our local network clients to connect to our remote host using IP
address 192.168.1.10, on the vpn server we run:

```
  sysctl -w net.ipv4.ip_forward=1
  iptables -t nat -A PREROUTING -d 192.168.1.10 -j DNAT --to-dest 10.0.0.2
  iptables -t nat -A POSTROUTING -d 10.0.0.2 -j SNAT --to-source 10.7.0.1
  arpreply -i eth0 -a 192.168.1.10
```

The arpreply tool will essentially fake the 192.168.1.10 presence on the network,
by redirecting all the incoming connections to the VPN server itself. On the
VPN server, the IPTABLES rules will nat the incoming traffic to our remote host.

Now anyone on the 192.168.1.0/24 network can connect to our remote host! For example,
192.168.1.25 could run `ssh 192.168.1.10`, and its request will be forwarded through
the VPN server to our remote host.

## Run arpreply

The package `python2` and `scapy` are required in order to run this program.

```
usage: arpreply [-h] --interface IFACE --ip-address ADDR [--mac MAC]

Respond to ARP requests by forging MAC address

optional arguments:
  -h, --help            show this help message and exit
  --interface IFACE, -i IFACE
                        Interface to listen ARP request on
  --ip-address ADDR, -a ADDR
                        The IP address to reply for
  --mac MAC, -m MAC     Spoofed MAC address to send on replies. If empty,
                        the interface MAC address will be used
```

In the simple case we just run something like `arpreply -i eth0 -a 192.168.1.10`.

## Archlinux package

An archlinux package is available! Please check out https://aur.archlinux.org/packages/arpreply-git .
