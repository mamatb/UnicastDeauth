# UnicastDeauth

* [What?](#what)
* [Why?](#why)
* [Installation](#installation)
* [Usage](#usage)
* [Disclaimer](#disclaimer)
* [Acknowledgements and references](#acknowledgements_and_references)

## What? <a name="what" />

UnicastDeauth is a simple Python 3 script that automates unicast Wi-Fi deauthentication attacks. In order to do so, it identifies all access points (APs) emitting the target ESSID and all connected stations (STAs), launching [Aircrack-ng's typical deauthentication](https://www.aircrack-ng.org/doku.php?id=deauthentication#typical_deauthentication) for each AP-STA tuple.

## Why? <a name="why" />

As [some STAs ignore broadcast deauthentication frames](https://www.aircrack-ng.org/doku.php?id=deauthentication#why_does_deauthentication_not_work), I've had to grab BSSIDs from `airodump-ng` to later specify them in `aireplay-ng` many times, so I thought of automating this process to save some time.

## Installation <a name="installation" />

```bash
git clone 'https://github.com/mamatb/UnicastDeauth.git'
pip install -r './UnicastDeauth/requirements.txt'
```

## Usage <a name="usage" />

As with all tools using Wi-Fi cards in monitor mode, first kill all processes that could interfere and then configure the Wi-Fi interface (as root):
```bash
airmon-ng check kill
ip link set dev "${WIFI_INTERFACE}" down
iw dev "${WIFI_INTERFACE}" set monitor control
iw dev "${WIFI_INTERFACE}" set channel "${WIFI_CHANNEL}"
ip link set dev "${WIFI_INTERFACE}" up
```
After that just follow the help section of the script:
```
usage: UnicastDeauth.py [-h] -i WIFI_INTERFACE -e ESSID [-b] [-n DEAUTH_ROUNDS] [-t APS_TARGETS] [-wl APS_WHITELIST]

UnicastDeauth is a simple Python 3 script that automates unicast Wi-Fi deauthentication attacks

options:
  -h, --help         show this help message and exit
  -i WIFI_INTERFACE  attacker Wi-Fi interface
  -e ESSID           target ESSID
  -b                 enable broadcast deauthentication
  -n DEAUTH_ROUNDS   number of deauthentication rounds
  -t APS_TARGETS     comma-separated known target APs
  -wl APS_WHITELIST  comma-separated APs whitelist

examples:
  UnicastDeauth.py -i wlan0 -e NETGEAR -b
  UnicastDeauth.py -i wlan0 -e NETGEAR -n 8
  UnicastDeauth.py -i wlan0 -e NETGEAR -t 00:11:22:33:44:00,00:11:22:33:44:55
  UnicastDeauth.py -i wlan0 -e NETGEAR -wl 00:11:22:33:44:00,00:11:22:33:44:55
```

## Disclaimer <a name="disclaimer" />

Please note that launching deauthentication attacks can be pretty noisy in certain environments. Also remember that they won't work if [Protected Management Frames](https://www.wi-fi.org/beacon/philipp-ebbecke/protected-management-frames-enhance-wi-fi-network-security) are in use.

## Acknowledgements and references <a name="acknowledgements_and_references" />

* [rsrdesarrollo](https://github.com/rsrdesarrollo) for helping me understand the Frame Control field and some Scapy basics. He also runs a Wi-Fi hacking suite called [pinecone](https://github.com/pinecone-wifi/pinecone) that you should definitely check out if interested in Wi-Fi hacking.
* [Scapy's usage documentation](https://scapy.readthedocs.io/en/latest/usage.html)
* [Aircrack-ng's deauthentication documentation](https://www.aircrack-ng.org/doku.php?id=deauthentication)
* [mrn-cciew's blogpost "CWAP – MAC Header : Addresses"](https://mrncciew.com/2014/09/28/cwap-mac-headeraddresses/)
* [mrn-cciew's blogpost "802.11 Mgmt : Deauth & Disassociation Frames"](https://mrncciew.com/2014/10/11/802-11-mgmt-deauth-disassociation-frames/)
