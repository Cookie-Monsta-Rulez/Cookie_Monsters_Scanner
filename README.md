# Cookie_Monsters_Scanner

![image](https://github.com/user-attachments/assets/0e956fb4-3437-4e79-8497-5fea7254a821)


A simple network scanner built in Python. The goal of this project was to make a scanner that is not necessarily signatured against nmap signatures. Being in Python also allows for quick adjustment on the fly to better evade scanning signatures. By no means is this to replace nmap, but another tool for your toolkit. 

## Installation

```
1. Clone the repository in full, or simply download "Cookie_Monsters_Scanner.py" 
2. python3 Cookie_Monsters_Scanner.py
```

## Technical Specifics

The tool utilizes two main methods for host detection and enumeration:

- Ping
- A TCP socket to the specified port

A singular ping will be sent to the target, and then if it is online it will be further enumerated using a TCP socket. Random sleep timers have been implemented to make the traffic look less like a structured scan, and more like random network traffic. 
 
It also performs simple banner grabbing if port 80 is specified by using netcat to connect to port 80 and grabbing the banner. 

## Usage

```
python3 Cookie_Monsters_Scanner.py -t <target network>/<cidr> -p <ports>,<Comma>,<separated> -b -o <outfile>
```

## Help

The help menu is as follows: 

```
  ____            _    _        __  __                 _            _     
 / ___|___   ___ | | _(_) ___  |  \/  | ___  _ __  ___| |_ ___ _ __( )___ 
| |   / _ \ / _ \| |/ / |/ _ \ | |\/| |/ _ \| '_ \/ __| __/ _ \ '__|// __|
| |__| (_) | (_) |   <| |  __/ | |  | | (_) | | | \__ \ ||  __/ |    \__ \
 \____\___/ \___/|_|\_\_|\___| |_|  |_|\___/|_| |_|___/\__\___|_|    |___/
                                                                          
 ____                                  
/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | (_| (_| | | | | | | |  __/ |   
|____/ \___\__,_|_| |_|_| |_|\___|_|   
                                       

usage: Cookie Monster's Scanner [-t ] [-b] [-h] [-f ] [-p ] [-o ]

This program is meant to be a light-weight alternate to nmap. While it does not have nearly as much functionality as nmap, it provides the operator
complete understanding and customization of how the connections are made. With the program being built from the ground-up, there is little to signature on
in regard to nmap signatures.

options:
  -t  , --target    Target
  -b, --banners     Perform Banner Grabbing
  -h, --help        You're looking at it baby!
  -f  , --file      Input file
  -p  , --ports     Port Specification (comma separated)
  -o  , --output    Output file

Have improvements? Want a feature implemented? Please feel free to reach out!
```

## Support
If you have any suggestions or improvements please feel free to reach out! 

## Roadmap
Some features to be implemented: 
- Randomize the hosts to ping 
- Asynchronous communication
- UDP feature
- Service version detection 

## Authors and acknowledgment
This project was made by Cookie-Monsta-Rulez

## Acknowledgements: 
- Smail for getting me started



