#!/bin/bash

# Run ClamAV
freshclam -d
clamd

bash /opt/updater.sh

python pypi-firewall.py
