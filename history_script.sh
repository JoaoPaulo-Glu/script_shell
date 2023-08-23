#!/bin/bash

# Obter a data e hora atuais:
date=$(date +"%Y-%m-%d %H:%M:%S")

# Obter uso de CPU:
cpu_usage=$(sar -u 1 1 | tail -1 | awk '{print $14}')

# Obter memoria usada:
memory_usage=$(free -m | awk 'NR==2 {print $3}')

# Escrever resultado no arquivo:
echo "Date: $date" >> cpu_memory_usage.log
echo "CPU Usage: $cpu_usage%" >> cpu_memory_usage.log
echo "Memory Usage: $memory_usage MB" >> cpu_memory_usage.log

# Salvar arquivo:
exit 0
