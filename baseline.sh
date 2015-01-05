#!/bin/bash
top -n 1 -b | grep "%Cpu(s):" | awk '{print $2}' >> cpu_baseline.txt
free -m | grep "Mem:" | awk '{print $3}' >> memory_baseline.txt
ifstat -i eth0 1 1 | awk 'FNR == 3 {print $1}' >> network_baseline.txt

