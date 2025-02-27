#!/usr/bin/python3 

import socket
import os
from tkinter import FIRST
import sys
import pyfiglet
import numpy as np
import subprocess
import time
import random
from termcolor import colored
import argparse
import re
import ipaddress
import datetime
from scapy.all import sniff, IP, AsyncSniffer, TCP, UDP, conf
import keyboard
conf.sniff_promisc = True
#######################################################################
#  Network and Port scanner developed by Sean Cooke 
#  Date created: 20231005
#  
#  Utilizes ping to verify a host is online, and then scans specified ports on
#  identified machines
#
#  Changelog: 20231005 - Created initial tool
#             20241125 - Added Port selection
#             20241127 - Added sleep functionality for detection evasion
#
#######################################################################

banner = pyfiglet.figlet_format("Cookie Monster's Scanner")
print(banner)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) 

###### variable declaration ###########
iprange = []
first_three_octets = ''
last_octet_start = 0
last_octet_last = 0
scanning_range = ''
int_last_octet_start = 0
int_last_octet_last = 0
online_hosts = []
banner_grab_http_answer = ''
shuffled_range = []
times_called = 0
location = ''
item = ''
numservices = 0
online_host_count = 0
sniff_ip_array = []
unique_ip_sniff_list = []
stop_sniffing = False
def main_func():
    global last_octet_start
    global last_octet_last
    global first_three_octets
    global iprange
    global online_hosts
    global scanning_range
    global ports
    global banners
    global output
    global shuffled_range
    global metaoutput
    global numservices
    global interface
    m = ' ' 
    parser = argparse.ArgumentParser(
                    prog='Cookie Monster\'s Scanner',
                    description='This program is meant to be a light-weight alternate to nmap. While it does not have nearly as much functionality as nmap, it provides the operator complete understanding and customization of how the connections are made. With the program being built from the ground-up, there is little to signature on in regard to nmap signatures.',
                    epilog='Have improvements? Want a feature implemented? Please feel free to submit a pull request!',
                    add_help=False)
    parser.add_argument('-t', '--target', help='Target', metavar=m, required=False)
    parser.add_argument('-b', '--banners', help='Perform Banner Grabbing', action="store_true", required=False)
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                    help='You\'re looking at it baby!')
    parser.add_argument('-f', '--file', help='Input file', metavar=m, required=False)
    parser.add_argument('-p', '--ports', help='Port Specification (comma separated)', metavar=m, required=False)
    parser.add_argument('-o', '--output', help='Output file', metavar=m, required=False)
    parser.add_argument('-m', '--meta', help='Metasploit Import Format',metavar=m, required=False)
    parser.add_argument('-P', '--passive', help='Passive Active Scanning Mode',metavar=m, required=False)
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser = argparse.ArgumentParser(description='This program is meant to be a light-weight alternate to nmap. While it does not have nearly as much functionality as nmap, it provides the operator complete understanding and customization of how the connections are made. With the program being built from the ground-up, there is little to signature on in regard to nmap signatures.')
        parser.print_help()
        sys.exit(1)
    input_network = args.target
    banners = args.banners
    output = args.output
    metaoutput = args.meta
    ports = args.ports
    interface = args.passive
    if (interface is not None):
        PassiveMode(interface)
        print(colored("Scan Complete!", 'green'))
        if (output is not None):
            cwd = os.getcwd()
            print(colored("Your loot is located at: " + cwd + "/" + output, 'blue'))
        if (metaoutput is not None):
            location = "last_host"
            reporter(location)
        sys.exit()
    numserviceslist = ports.split(',')
    for num in numserviceslist:
        numservices = numservices + 1
    if (metaoutput is not None): 
        initialize = 0
        reporter(initialize)
    check_target(input_network)
    cidr_notation_determination(input_network)
    #shuffle_array(network_range)
    ip_range_scanner(network_range)
    online_hosts_port_scanner(online_hosts)
    print(colored("Scan Complete!", 'green'))
    if (output is not None):
        cwd = os.getcwd()
        print(colored("Your loot is located at: " + cwd + "/" + output, 'blue'))
    if (metaoutput is not None):
        location = "last_host"
        reporter(location)
    return 0; 

def reporter(*args):
    global metaoutput
    global numservices
    global ports
    global initialize
    global online_host_count
    loot_file = open( str(metaoutput), 'a')
    if (len(args) == 1 and args[0] == 0):
        now = datetime.datetime.now()
        loot_file.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "\n")
        loot_file.write("<!DOCTYPE nmaprun>" + "\n")
        loot_file.write("<?xml-stylesheet href=\"file:///usr/share/nmap/nmap.xsl\" type=\"text/xsl\"?>" + "\n")
        loot_file.write("<!-- Nmap 7.95 scan initiated " + str(now) + " as: /usr/lib/nmap/nmap -oA nmap-test 192.168.1.1 -->" + "\n")
        loot_file.write("<nmaprun scanner=\"nmap\" version=\"7.95\" xmloutputversion=\"1.05\">" + "\n")
        loot_file.write("<scaninfo type=\"syn\" protocol=\"tcp\"" +  " numservices=\"" + str(numservices) + "\" services=\"" + str(ports) + "\" />" + "\n")
        initialize = 1 
    if (len(args) == 2 and args[0] == "new_host"):
        online_host = args[1]
        loot_file.write("<hosthint><status state=\"up\" reason=\"unknown-response\" reason_ttl=\"0\"/>" + "\n")
        loot_file.write("<address addr=\"" + str(online_host) +  "\" addrtype=\"ipv4\"/>" + "\n")
        loot_file.write("<hostnames>" + "\n")
        loot_file.write("</hostnames>" + "\n")
        loot_file.write("</hosthint>" + "\n")
        loot_file.write("<host starttime=\"1739377800\" endtime=\"1739377800\"><status state=\"up\" reason=\"reset\" reason_ttl=\"128\"/>" + "\n")
        loot_file.write("<address addr=\"" + str(online_host) +  "\" addrtype=\"ipv4\"/>" + "\n")
        loot_file.write("<hostnames>" + "\n")
        loot_file.write("</hostnames>" + "\n")
        loot_file.write("<ports>")
    if (len(args) == 3 and args[0] == "new_port"):
        port = args[1]
        state = args[2]
        loot_file.write("<port protocol=\"tcp\" portid=\"" + str(port) + "\"><state state=\"" + str(state) + "\" reason=\"syn-ack\" reason_ttl=\"128\"/><service name=\"http\" method=\"table\" conf=\"3\"/></port>" + "\n")
    if (len(args) == 1 and args[0] == "last_port"):  
        loot_file.write("</ports>" + "\n")
        loot_file.write("<times srtt=\"602\" rttvar=\"4268\" to=\"100000\"/>" + "\n")
        loot_file.write("</host>" + "\n")
    if (len(args) == 1 and args[0] == "last_host"):
        loot_file.write("<runstats><finished time=\"1739377795\" timestr=\"Wed Feb 12 11:29:55 2025\" summary=\"Nmap done at Wed Feb 12 11:29:55 2025; " + str(online_host_count) + " IP addresses ( " + str(online_host_count) + " hosts up) scanned in 0.15 seconds\" elapsed=\"0.15\" exit=\"success\"/><hosts up=\"" + str(online_host_count) + "\" down=\"0\" total=\"" + str(online_host_count) + "\"/>" + "\n")
        loot_file.write("</runstats>" + "\n")
        loot_file.write("</nmaprun>" + "\n")
    loot_file.close()

def process_packet(packet):
    global sniff_ip_array
    global unique_ip_sniff_list
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}, Source Port: {port_src} -> Destination Port: {port_dst}")
        elif UDP in packet:
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}, Source Port: {port_src} -> Destination Port: {port_dst}")
        sniff_ip_array.append(ip_src)
        sniff_ip_array.append(ip_dst)
        unique_ip_sniff_list = list(set(sniff_ip_array))

# Define a function to be called when Ctrl + S is pressed
def on_ctrl_s():
    global stop_sniffing
    stop_sniffing = True
    print(colored("Ctrl + S was pressed! Stopping sniffing...", 'green'))

# Hook the function to the Ctrl + S key combination
keyboard.add_hotkey('ctrl+s', on_ctrl_s)

def process_packet(packet):
    global unique_ip_sniff_list
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}, Source Port: {port_src} -> Destination Port: {port_dst}")
        elif UDP in packet:
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            print(f"Source IP: {ip_src} Source Port: {port_src} -> Destination IP: {ip_dst} Destination Port: {port_dst}")
        sniff_ip_array.append(ip_src)
        sniff_ip_array.append(ip_dst)
        unique_ip_sniff_list = list(set(sniff_ip_array))


def PassiveMode(*args):
    global online_hosts
    if (os.geteuid() != 0):
        print(colored("For Passive Mode you must run with sudo\n", 'red'))
        sys.exit(1)
    global stop_sniffing
    # Use AsyncSniffer for non-blocking sniffing
    sniffer = AsyncSniffer(filter="ip", prn=process_packet)
    sniffer.start()
    print(colored("Press Ctrl + S to stop sniffing", 'green'))
    while not stop_sniffing:
        pass  # Keep the loop running until stop_sniffing is True
    sniffer.stop()
    for found_host in unique_ip_sniff_list:
        user_input = input(colored(f"Scan {found_host}? (Y/N): ", 'yellow')).strip().lower()
        user_input = re.sub(r'[\x00-\x1F\x7F]', '', user_input)
        if (user_input == 'y'):
            online_hosts.append(found_host)
        else:
            print(colored(f"Skipping {found_host}", 'yellow'))
    online_hosts_port_scanner(online_hosts)

def outputer(*args):
    global location
    global item
    global output
    if (location == "discovery"):
        loot_file = open( str(output), 'a')
        if (times_called == 0):
            if (metaoutput == 0): 
                loot_file.write("---------- ONLINE HOSTS ----------\n")
        loot_file.write(str(item) + "\n")
        loot_file.close()
    elif (location == "port_discovery"):
        loot_file = open( str(output), 'a')  
        if (times_called == 0):
             loot_file.write("---------- PORT DISCOVERY ----------\n")
        if (len(args) == 3 and args[2] == "new_host"):
            loot_file.write("Report for host: " + str(args[1]) + "\n")
        if (len(args) == 3 and args[2] == "port"):
            loot_file.write("Port No: {} is Open".format(item) + " \n")
        loot_file.close()

def shuffle_array(array_range):
    global shuffled_range
    temp_range = array_range[:]  # Create a copy to avoid modifying the original
    shuffled_range = []
    
    while True:
        try:
            # Generate a random index within the remaining elements
            index = random.randrange(0, len(temp_range))
            # Append the element at the random index to the shuffled array
            shuffled_range.append(temp_range.pop(index))
        except ValueError:
            # Break the loop when temp_arr is empty (no more elements to pick)
            break
    
    return shuffled_range

def ip_range_scanner(network_range):
    global online_hosts
    global shuffled_range
    global output
    global location
    global times_called
    global item
    print(colored("Scanning range: " + str(network_range), 'green'))
    range_array = list(network_range.hosts())
    shuffle_array(range_array)
    for host in shuffled_range:
        try:
            with open(os.devnull, 'w') as DEVNULL:
                try:
                    subprocess.check_call(
                        ['ping', '-c', '1', str(host)],
                        stdout=DEVNULL,
                        stderr=DEVNULL
                    )
                    is_up = True
                    print(colored("Host " + str(host) + " is up!", 'green' ))
                    online_hosts.append(str(host))
                    if (output != 0):
                        location = "discovery"
                        item = host
                        outputer(location, item)
                        times_called = 1
                    time.sleep(random.random())
                except subprocess.CalledProcessError:
                    is_up = False
                    print(colored("Host " + str(host) + " is down!", 'red'))
                    time.sleep(random.random())
        except socket.gaierror as e:
            print(colored("IP address not online" + str(host), 'red'))
        continue
    print(colored("These hosts are online: " + str(online_hosts), 'green'))
    times_called = 0 

def check_target(input_network):
    global network_range
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([/][0-3][0-2]?|[/][1-2][0-9]|[/][0-9])?$"
    result = re.match(pattern, input_network)
    if (result == None):
        print(colored("Please enter a valid network IP range and/or a valid CIDR", 'red'))
        sys.exit()
    network_range = ipaddress.ip_network(input_network, strict=False) 


def cidr_notation_determination(network_range):
    global cidr_determined
    cidr_array = network_range.split("/")
    cidr_input = cidr_array[1]
    cidr_list = {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, '10': 10, '11': 11, '12': 12, '13': 13, '14': 14, '15': 15, '16': 16, '17': 17, '18': 18, '19': 19, '20': 20, '21': 21, '22': 22, '23': 23, '24': 24, '25': 25, '26': 26, '27': 27, '28': 28, '29': 29, '30': 30, '31': 31, '32': 32}
    if cidr_input not in cidr_list: 
        print(colored("Please enter a valid CIDR Notation value.", 'red'))
        sys.exit()       

def online_hosts_port_scanner(online_hosts):
    global online_host_count
    online_host_count = len(online_hosts)
    global output
    global location
    global times_called
    global item
    global numservices
    index = 0
    print(colored("Moving to port scanning on: " + str(online_host_count) + " hosts!", 'green'))
    random_online_hosts = random.shuffle(online_hosts)
    for online_host in online_hosts:
        print(colored("Currently scanning ports on host: " + online_host, 'yellow'))
        index2 = 0
        if (metaoutput is not None):
            location = "new_host"
            reporter(location, online_host)
        if (output != 0):
            report = "new_host"
            location = "port_discovery"
            outputer(location, online_host, report)
            times_called = 1
        try:
            port_list = ports.split(',')
            for port in port_list:
                index2 = index2 + 1
                port = int(port)
                serv = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                serv.settimeout(random.random())
                scan = serv.connect_ex((online_host, port))
                serv.close()
                if scan == 0:
                    print(colored("Port No: {} is Open ".format(port) + "on host: " + online_host, 'green'))
                    if (metaoutput is not None):
                        location = "new_port"
                        state = "open"
                        reporter(location, port, state)
                    if (output != 0):
                        item = port
                        report = "port"
                        outputer(location, online_host, report)
                    if (port == 80) and (banners != 0):
                        print(colored("Grabbin Banners!", 'yellow'))
                        port = str(port) 
                        banner_file = open('banners.txt', 'a')  
                        banner_file.write("------- Banner for: " + str(online_host) + " -------\n")
                        banner_file.flush()
                        with open("banners.txt", "a+") as file:
                            time.sleep(3)
                            process = subprocess.Popen(
                                ["nc", online_host, str(port)],
                                stdin=subprocess.PIPE, 
                                stdout=file, 
                                stderr=subprocess.PIPE,
                                text=True
                            )
                            request = "GET / HTTP/1.0\n\n"
                            stdout, stderr = process.communicate(input=request)
                            process.terminate()
                        banner_file.write("--------------------------------\n")
                        banner_file.flush()
                else: 
                    print(colored("Port No: {} is closed".format(port), 'red'))
                    if (metaoutput is not None):
                        location = "new_port"
                        state = "closed"
                        reporter(location, port, state)
                    if (output != 0):
                        loot_file = open( str(output), 'a')  
                        loot_file.write("Port No: {} is closed".format(port) + " \n")
                        loot_file.close()
                    time.sleep(random.random())
            if (index2 == numservices and metaoutput is not None):
                        location = "last_port"
                        reporter(location)
        except socket.gaierror as e:
            print(colored("IP address not online" + host, 'red'))
        index = index + 1
        continue
         
main_func()
