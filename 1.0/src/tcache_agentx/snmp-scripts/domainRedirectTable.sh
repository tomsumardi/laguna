#!/bin/bash

snmpwalk -Os -c private -v1 localhost 1.3.6.1.4.1.1457.4.1.1.6
exit 0
