#!/bin/sh

#
# Example of how to run ampr-ripd
#
# In this case:
# - received routes are saved to /var/lib/ampr-ripd/encap.txt
# - the tunnel interface is called ampr0
# - you have to run the program in debug mode (-d) to find the password...
# - the ip 193.0.0.1 is excluded from the list (the public ip, if not directly connected to a interface,
#   replace with your own IP if you need this or just delete the parameter)
# - all routes are created using metric 50 (allows for other ampr routes with smaller metric to take precedence,
#   e.g. routes aquired via other routing protocols, may be dropped if not needed)
# - all received RIPv2 multicasts are forwarded to interface eth0 as multicasts (drop this if not needed)...
# - all routes set by ampr-ripd are saved to /var/lib/ampr-ripd/routes (example of external system command)
#

/usr/sbin/ampr-ripd -s -i ampr0 -m 50 -a 193.0.0.1 -f eth0 -x "ip route | grep 'proto 44' >/var/lib/ampr-ripd/routes"
