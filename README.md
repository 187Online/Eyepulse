#                                  Eyepulse 

## About Eyepulse  
Eyepulse is a versatile Python port scanning tool with 14 methods
* Get ip address
* Control server 
* Show port list 
* Fast scan
* Full scan
* Range scan
* Ping scan
* ICMP scan
* Net recon
* Stealth scan
* TCP/ACK scan
* XMAS scan
* Zombie scan
* UDP scan


## Module Requirement
* scapy 
* pythonping  
* argparse 
* prettytable 

## ⚠️ Usage Warnings ⚠️
* Select the device with the least traffic on your network for zombie scanning, otherwise it may  not work as expected
* If you encounter a Scapy pcap error, try installing Wireshark and try again

## Languages

**%100 Python**

## Usage

Installation :

```bash
  git clone  https://github.com/187Online/Eyepulse.git

```

Go to project file :

```bash
  cd project_file
```

Get help :

```bash
  python eyepulse.py 
```

Example :

```bash
  python eyepulse.py -sS -sA 192.168.1.1 -tO 3
```
## License

[MIT](https://choosealicense.com/licenses/mit/)

## 

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/)
[![AGPL License](https://img.shields.io/badge/license-AGPL-blue.svg)](http://www.gnu.org/licenses/agpl-3.0)
