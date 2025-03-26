import argparse
import re
import sys
import signal
import threading
import time
from ast import literal_eval

import can

from scapy.config import conf
from scapy.layers.can import CandumpReader

try:
    import scapy.libs.six as six

    if six.PY2:
        conf.contribs["CANSocket"] = {"use-python-can": True}
except ModuleNotFoundError:
    pass
from scapy.consts import LINUX

if not LINUX or conf.use_pypy:
    conf.contribs["CANSocket"] = {"use-python-can": True}

from scapy.scapypipes import WiresharkSink, WrpcapSink, SniffSource
from scapy.sendrecv import sniff, AsyncSniffer
from scapy.contrib.cansocket import CANSocket, PYTHON_CAN  # noqa: E402
from scapy.contrib.isotp import ISOTPSocket

from scapy.contrib.automotive.uds import UDS

from scapy.pipetool import CLIFeeder, ConsoleSink, PipeEngine, Sink


def create_socket(python_can_args, interface, channel, bitrate):
    if PYTHON_CAN:
        if python_can_args:
            interface_string = "PythonCANSocket(interface=" "'%s', channel='%s', %s)" % (
                interface,
                channel,
                python_can_args,
            )
            arg_dict = dict(
                (k, literal_eval(v))
                for k, v in (
                    pair.split("=") for pair in re.split(", | |,", python_can_args)
                )
            )
            sock = CANSocket(
                interface=interface, channel=channel, bitrate=bitrate, **arg_dict
            )
        else:
            interface_string = "PythonCANSocket(interface=" "'%s', channel='%s')" % (
                interface,
                channel,
            )
            sock = CANSocket(interface=interface, channel=channel, bitrate=bitrate)
    else:
        sock = CANSocket(channel=channel)
        interface_string = '"%s"' % channel

    return sock, interface_string


def sanitize_string(input_string):
    s = input_string.replace("interface", "").replace("channel", "")
    s = "".join(ch if ch.isalnum() else "_" for ch in s)
    s = re.sub("_+", "_", s)  # replace multiple underscores with a single one
    s = re.sub("_+$", "", s)  # remove trailing underscores
    return s


def main():
    parser = argparse.ArgumentParser(
        description="print a canlog and capture to a pcap using scapy"
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        required=False,
        help="""python-can interface for the scan.
                          Depends on used interpreter and system,
                          see examples below. Any python-can interface can
                          be provided. Please see:
                          https://python-can.readthedocs.io for
                          further interface examples.""",
    )
    parser.add_argument(
        "-c",
        "--channel",
        type=str,
        required=False,
        help="Additional arguments for a python-can Bus object.",
    )
    parser.add_argument(
        "-b",
        "--bitrate",
        type=int,
        required=False,
        default=500_000,
        help="Bits per second.",
    )
    parser.add_argument(
        "-a",
        "--python-can_args",
        type=str,
        required=False,
        help="python-can channel or Linux SocketCAN interface name",
    )
    parser.add_argument(
        "-w", "--write", type=str, required=False, help="Output pcap file"
    )
    parser.add_argument(
        "-q", "--silent", type=bool, required=False, default=False, help="Silent mode"
    )
    parser.add_argument(
        "-f", "--file", type=str, required=False, help="read from a candump instead"
    )

    args = parser.parse_args()

    if args.file is not None:
        sock = CandumpReader(args.file)
        interface_string = "log"
    else:
        sock, interface_string = create_socket(
            args.python_can_args, args.interface, args.channel, args.bitrate
        )

    pretty_iface_name = sanitize_string(interface_string)

    class PrintSink(Sink):
        def push(self, pkt):
            print(
                f"({pkt.time:010.06f}) {pretty_iface_name} {pkt.identifier:03x}#{pkt.data.hex()}"
            )
            return

        def high_push(self, msg):
            return

    packet_count = 0
    feeder = CLIFeeder()
    if not args.silent:
        printer = PrintSink()
        feeder > printer
    if args.write is not None:
        wire = WrpcapSink(args.write)
        feeder > wire

    p = PipeEngine(feeder)
    p.start()

    def just_feed(p):
        nonlocal packet_count
        if not args.silent:
            feeder.send(p)
        packet_count = packet_count + 1
        return
    sniff(opened_socket=sock, prn=just_feed, store=0)

    sock.close()
    ## scapy / python-can BUG WORKAROUND: the end of the `with` block above .close()es the `csock2` which also deletes and
    # closes the underlying python-can interface. If we don't monkey-patch the `low_csock.closed` then the result will be a
    # deep stacktrace while python is shutting down later
    sock.closed = True
    sock.can_iface._is_shutdown = True

    p.stop()
    p.wait_and_stop()

    sys.stderr.write("processed %d packets\n" % packet_count)

if __name__ == "__main__":
    main()
