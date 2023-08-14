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
ip link set dev <wifi_interface> down
iw dev <wifi_interface> set monitor control
iw dev <wifi_interface> set channel <wifi_channel>
ip link set dev <wifi_interface> up

```
After that just follow the help section of the script:
```
usage: UnicastDeauth.py [-h] -i WIFI_INTERFACE -e WIFI_ESSID

options:
  -h, --help         show this help message and exit
  -i WIFI_INTERFACE  Wi-Fi interface
  -e WIFI_ESSID      Wi-Fi ESSID
```

## Disclaimer <a name="disclaimer" />

Please note that launching deauthentication attacks can be pretty noisy in certain environments. So hack responsibly or something like that.

## Acknowledgements and references <a name="acknowledgements_and_references" />

* [rsrdesarrollo](https://github.com/rsrdesarrollo) for helping me understand the Frame Control field and some Scapy basics. He also runs a Wi-Fi hacking suite called [pinecone](https://github.com/pinecone-wifi/pinecone) that you should definitely check out if interested in Wi-Fi hacking.
* [Scapy's usage documentation](https://scapy.readthedocs.io/en/latest/usage.html)
* [Aircrack-ng's deauthentication documentation](https://www.aircrack-ng.org/doku.php?id=deauthentication)
* [mrn-cciew's blogpost "CWAP – MAC Header : Addresses"](https://mrncciew.com/2014/09/28/cwap-mac-headeraddresses/)
* [mrn-cciew's blogpost "802.11 Mgmt : Deauth & Disassociation Frames"](https://mrncciew.com/2014/10/11/802-11-mgmt-deauth-disassociation-frames/)