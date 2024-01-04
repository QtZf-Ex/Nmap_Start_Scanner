#!/bin/bash
# Fast network scan using nmap
sudo nmap -Pn -sS -n -v -p21,22,23,25,80,443,445,1433,1540,2049,2222,3306,3389,5432,5900,5901,6379,8000,8001,8002,8008,8080,8081,8082,8088,8443,8800,8888,9200,27017 --min-rate 300 --min-parallelism 100 -iL scope.txt -oA nmap --open

# Parsing nmap results to extract IP addresses and open ports
while read -r line; do
    if [[ $line =~ "Nmap scan report for" ]]; then
        ip=$(echo "$line" | grep -Eo '([0-9]+\.){3}[0-9]+')
    elif [[ $line =~ "open" ]]; then
        port=$(echo "$line" | grep -Eo '^[0-9]+')
        echo "$ip:$port" >> IP_PORT.txt
    fi
done < nmap.nmap

# Run nuclei in the background to detect technologies
nuclei -l IP_PORT.txt -o nuclei_res.txt &

# Capture screenshots of service pages
while read -r ip_port; do
    cutycapt --url="$ip_port" --out="$ip_port.png"
done < IP_PORT.txt

# Extract IP addresses with port 22 open
awk -F: '$2 == 22' IP_PORT.txt | cut -d: -f1 > 22_port.txt

# Search for root:root authorization on port 22 using patator
patator ssh_login host=FILE0 user=root password=root 0=22_port.txt -x ignore:mesg='Authentication failed.' -t 100 -R patator_22_res.txt
