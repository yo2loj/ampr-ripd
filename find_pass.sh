#!/bin/sh

#
# Running ampr-ripd without any options except debug and the interface name
# allows you to find your RIPv2 password if it ever changes from the default.
# You need to adapt the interface name to your setup.
#

./ampr-ripd -d -i ampr0
