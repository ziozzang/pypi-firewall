#!/bin/bash

# Run ClamAV
chown -R 102:104 /var/run/clamav/ /var/lib/clamav/

freshclam -d
clamd

bash /opt/updater.sh > /dev/null 2>&1 &
python pypi-firewall.py
