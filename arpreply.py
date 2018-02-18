#!/bin/env python2
#
# arpreply
# (C) 2018 Emanuele Faranda
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import fcntl, socket, struct
import argparse
import logging

# https://stackoverflow.com/questions/159137/getting-mac-address
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

def packetLoop(iface, reply_mac, responder_address):
  from scapy.all import *
  logging.info("Starting packet poll loop")

  while True:
    packets = sniff(filter="arp and host " + responder_address, count=1)
    #packets.summary()
    arp_request = packets[0]
    #arp_request.show()

    client_mac = arp_request.hwsrc
    client_ip = arp_request.psrc

    logging.info("ARP request: %s (%s) asks who is %s, reply %s" % (client_ip, client_mac, responder_address, reply_mac))

    reply = Ether()/ARP()
    reply.op = 2
    reply.psrc = responder_address
    reply.pdst = client_ip
    reply.hwdst = client_mac
    reply.hwsrc = reply_mac
    reply[Ether].src = reply_mac
    reply[Ether].dst = client_mac
    #reply.show()
    sendp(reply, verbose=False, iface=iface)

def parseArgs():
  parser = argparse.ArgumentParser(
    prog="arpreply",
    description="Respond to ARP requests by forging MAC address",
    formatter_class=argparse.RawTextHelpFormatter,
    epilog='''example:

 Respond to IP address 192.168.1.10 ARP requests with eth0 interface mac address
   sudo ./arpreply.py -i eth0 -a 192.168.1.10''')

  parser.add_argument("--interface", "-i", dest = "iface",
    help="Interface to listen ARP request on", type=str, required=True)
  parser.add_argument("--ip-address", "-a", dest = "addr",
    help="The IP address to reply for", type=str, required=True)
  parser.add_argument("--mac", "-m", dest = "mac",
    help="Spoofed MAC address to send on replies. If empty,\nthe interface MAC address will be used", type=str, default="")

  return parser.parse_args()

if __name__ == "__main__":
  args = parseArgs()

  logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)
  mac = args.mac

  if not mac:
    try:
      mac = getHwAddr(args.iface)
    except IOError:
      logging.error("Could not get interface %s mac address, please specify it manually (-m option)" % args.iface)
      exit(1)

  packetLoop(args.iface, mac, args.addr)
