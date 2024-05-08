import argparse
import re

from ast import literal_eval

from scapy.all import sniff, wrpcap
import scapy.libs.six as six
from scapy.config import conf
from scapy.consts import LINUX

if six.PY2 or not LINUX or conf.use_pypy:
    conf.contribs["CANSocket"] = {"use-python-can": True}

from scapy.contrib.cansocket import CANSocket, PYTHON_CAN  # noqa: E402


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
        required=True,
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

    args = parser.parse_args()

    sock, interface_string = create_socket(
        args.python_can_args, args.interface, args.channel, args.bitrate
    )

    pretty_iface_name = sanitize_string(interface_string)

    def packet_handler(pkt):
        print(
            f"({pkt.time:010.06f}) {pretty_iface_name} {pkt.identifier:03x}#{pkt.data.hex()}"
        )
        if args.write is not None:
            wrpcap(args.write, pkt, append=True)

    sniff(opened_socket=sock, prn=packet_handler)


if __name__ == "__main__":
    main()
