#!/bin/bash

snmpwalk -Os -c private -v1 localhost 1.3.6.1.4.1.1457.4.1.1.18
exit 0
