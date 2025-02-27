# Cookie_Monsters_Scanner

![alt text](img/393377289-0e956fb4-3437-4e79-8497-5fea7254a821.png)

A simple network scanner built in Python. The goal of this project was to make a scanner that is not necessarily signatured against nmap signatures. Being in Python also allows for quick adjustment on the fly to better evade scanning signatures. By no means is this to replace nmap, but another tool for your toolkit. 

## Installation

Windows:
```
git clone --recursive https://github.com/Cookie-Monsta-Rulez/Cookie_Monsters_Scanner.git 
cd Cookie_monster_Scanner
python -m virtualenv venv
venv\scripts\activate.bat || source venv/bin/activate
pip install -r requirements.txt
python Cookie_Monsters_Scanner.py -h
```

Linux: 
```
git clone --recursive https://github.com/Cookie-Monsta-Rulez/Cookie_Monsters_Scanner.git
cd Cookie_Monsters_Scanner
python3 Cookie_Monsters_Scanner
```

## Technical Specifics

The tool utilizes two main methods for host detection and enumeration:

- Ping
- A TCP socket to the specified port

A singular ping will be sent to the target, and then if it is online it will be further enumerated using a TCP socket. Random sleep timers have been implemented to make the traffic look less like a structured scan, and more like random network traffic. 
 
It also performs simple banner grabbing if port 80 is specified by using netcat to connect to port 80 and grabbing the banner. 

## Passive Mode
Passive mode allows for listening on the specified interface. When desired, "ctrl + S" can be pressed to ask if the detected IP addresses should be scanned. The IP addresses will be scanned against the ports specified. 

## Usage

```
python Cookie_Monsters_Scanner.py -t <target network>/<cidr> -p <ports>,<Comma>,<separated> -b -o <outfile>
```

# Metasploit Compatibility
There is limited Metasploit compatibility. Using -m will output to an nmap xml format which can be imported to Metasploit. However, it currently lists all services as "HTTP".

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


usage: Cookie Monster's Scanner [-t ] [-b] [-h] [-f ] [-p ] [-o ] [-m ] [-P ]

This program is meant to be a light-weight alternate to nmap. While it does not have nearly as much functionality as nmap, it provides the operator complete
understanding and customization of how the connections are made. With the program being built from the ground-up, there is little to signature on in regard to nmap     
signatures.

options:
  -t  , --target     Target
  -b, --banners      Perform Banner Grabbing
  -h, --help         You're looking at it baby!
  -f  , --file       Input file
  -p  , --ports      Port Specification (comma separated)
  -o  , --output     Output file
  -m  , --meta       Metasploit Import Format
  -P  , --passive    Passive Active Scanning Mode

Have improvements? Want a feature implemented? Please feel free to submit a pull request!
```

## Support
If you have any suggestions or improvements please feel free to submit a pull request!

## Roadmap
Some features to be implemented: 
- Asynchronous communication
- UDP feature
- Service version detection 
- Metasploit service functionality

## Authors and acknowledgment
This project was made by Cookie-Monsta-Rulez

## Contributions
- TheDyingYAK added compatability and the virtual environment portion 

## Acknowledgements: 
- Smail for getting me started



