#!/bin/bash

# Set the path to the nmap executable
NMAP_EXEC=/usr/bin/nmap

# Perform an ARP scan and save the results to a file
arp-scan -l | awk '{print $1}' > arp_scan_results.txt

# Perform an ICMP scan and save the results to a file
nmap -sn -Pn -6 -oG icmp_scan_results.txt 192.168.1.0/24

# Merge the ARP scan results and ICMP scan results
cat arp_scan_results.txt icmp_scan_results.txt | sort | uniq > devices.txt

# Get the information for each device
for device in $(cat devices.txt); do

    # Get the device's IP address
    ip_address=$device

    # Get the device's hostname
    hostname=$(nmap -sn -Pn -6 -T1 $ip_address | grep -oE "Nmap scan report for ([^ ]+)")
    hostname=${hostname#Nmap scan report for }

    # Get the device's operating system
    operating_system=$(nmap -O $ip_address | grep -oE "OS: ([^(]+)")
    operating_system=${operating_system#OS: }

    # Get the device's open ports
    open_ports=$(nmap -sS -T4 $ip_address | grep -oE "open  ([0-9]+)/")
    open_ports=${open_ports#open }

    # Display the information for the device
    echo "Device IP: $ip_address"
    echo "Device hostname: $hostname"
    echo "Device operating system: $operating_system"
    echo "Device open ports: $open_ports"

done

# Remove the temporary files
rm arp_scan_results.txt icmp_scan_results.txt devices.txt
