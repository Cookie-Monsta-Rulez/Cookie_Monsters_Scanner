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

def ip_range_scanner(network_range):
    #iprangearray = np.asarray(iprange)
    global online_hosts
    global output
    print(colored("Scanning range: " + str(network_range), 'green'))
    for host in network_range.hosts():
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
                        loot_file = open( str(output), 'a')  
                        loot_file.write("Host " + str(host) + " is up!\n")
                        loot_file.close()
                    time.sleep(random.random())
                except subprocess.CalledProcessError:
                    is_up = False
                    print(colored("Host " + str(host) + " is down!", 'red'))
                    time.sleep(random.random())
        except socket.gaierror as e:
            print(colored("IP address not online" + str(host), 'red'))
        continue
    print(colored("These hosts are online: " + str(online_hosts), 'green'))

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
    online_host_count = len(online_hosts)
    global output
    print(colored("Moving to port scanning on: " + str(online_host_count) + " hosts!", 'green'))
    for online_host in online_hosts:
        print(colored("Currently scanning ports on host: " + online_host, 'yellow'))
        if (output != 0):
            loot_file = open( str(output), 'a')  
            loot_file.write("Ports on host: " + online_host + " \n")
            loot_file.close()
        try:
            port_list = ports.split(',')
            for port in port_list:
                port = int(port)
                serv = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                serv.settimeout(random.random())
                scan = serv.connect_ex((online_host, port))
                serv.close()
                if scan == 0:
                    print(colored("Port No: {} is Open ".format(port) + "on host: " + online_host, 'green'))
                    if (output != 0):
                        loot_file = open( str(output), 'a')  
                        loot_file.write("Port No: {} is Open ".format(port) + " \n")
                        loot_file.close()
                    if (port == 80) and (banners != 0):
                        print(colored("Grabbin Banners!", 'yellow'))
                        port = str(port)
                        banner_file = open( 'banners.txt', 'a')  
                        banner_file.write("------- Banner for: " + str(online_host) + " -------\n")
                        banner_grab = subprocess.Popen(["nc", online_host, port], stdin=subprocess.PIPE, stdout=banner_file)
                        banner_grab.stdin.write(b"GET / HTTP/1.0")
                        banner_grab.stdin.write(b"\n")
                        banner_file.close()
                        cwd = os.getcwd()
                        print(colored("The banner was saved at: " + cwd + "/banners.txt", 'blue' ))
                        time.sleep(random.random())
                else: 
                    print(colored("Port No: {} is closed".format(port), 'red'))
                    if (output != 0):
                        loot_file = open( str(output), 'a')  
                        loot_file.write("Port No: {} is closed".format(port) + " \n")
                        loot_file.close()
                    time.sleep(random.random())
        except socket.gaierror as e:
            print(colored("IP address not online" + host, 'red'))
        continue

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
    m = ' ' 
    parser = argparse.ArgumentParser(
                    prog='Cookie Monster\'s Scanner',
                    description='This program is meant to be a light-weight alternate to nmap. While it does not have nearly as much functionality as nmap, it provides the operator complete understanding and customization of how the connections are made. With the program being built from the ground-up, there is little to signature on in regard to nmap signatures.',
                    epilog='Have improvements? Want a feature implemented? Please feel free to reach out!',
                    add_help=False)
    parser.add_argument('-t', '--target', help='Target', metavar=m, required=False)
    parser.add_argument('-b', '--banners', help='Perform Banner Grabbing', action="store_true", required=False)
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                    help='You\'re looking at it baby!')
    parser.add_argument('-f', '--file', help='Input file', metavar=m, required=False)
    parser.add_argument('-p', '--ports', help='Port Specification (comma separated)', metavar=m, required=False)
    parser.add_argument('-o', '--output', help='Output file', metavar=m, required=False)
    args = parser.parse_args()
    input_network = args.target
    banners = args.banners
    output = args.output
    check_target(input_network)
    cidr_notation_determination(input_network)
    ports = args.ports
    ip_range_scanner(network_range)
    online_hosts_port_scanner(online_hosts)
    print(colored("Scan Complete!", 'green'))
    if (output != 0):
        cwd = os.getcwd()
        print(colored("Your loot is located at: " + cwd + "/" + output, 'blue'))
    return 0; 
         
main_func()
