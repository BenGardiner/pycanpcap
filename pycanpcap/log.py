import argparse
import gzip
import os
import re
import sys
import time
from ast import literal_eval

from scapy.config import conf
from scapy.layers.can import CandumpReader, CAN
from scapy.plist import PacketList

PYTHON_CAN_LOGGER_FORMAT_PATTERN = (r"^Timestamp:\s+(\d+\.\d+)\s+ID:\s+([0-9a-fA-F]+)\s+(X\s+)?(Rx|Tx)\s+DL:\s+(["
                                    r"0-8])\s+([0-9a-fA-F\s]*)$")

try:
    import scapy.libs.six as six

    if six.PY2:
        conf.contribs["CANSocket"] = {"use-python-can": True}
except ModuleNotFoundError:
    pass
from scapy.consts import LINUX

if not LINUX or conf.use_pypy:
    conf.contribs["CANSocket"] = {"use-python-can": True}

from scapy.scapypipes import WrpcapSink
from scapy.sendrecv import sniff
from scapy.contrib.cansocket import CANSocket, PYTHON_CAN  # noqa: E402
from scapy.pipetool import CLIFeeder, PipeEngine, Sink


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


def is_python_can_logger_format(file):
    try:
        with open(file, 'r') as file:
            first_line = file.readline()
            return first_line.startswith('Timestamp:')

    except FileNotFoundError:
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


class PythonCanLoggerReader:
    nonblocking_socket = True

    def __init__(self, filename, interface=None):
        self.filename, self.f = self.open(filename)
        self.ifilter = None
        if interface is not None:
            if isinstance(interface, str):
                self.ifilter = [interface]
            else:
                self.ifilter = interface

    def __iter__(self):
        return self

    @staticmethod
    def open(filename):
        if isinstance(filename, str):
            try:
                fdesc = gzip.open(filename, "rb")
                fdesc.read(1)
                fdesc.seek(0)
            except IOError:
                fdesc = open(filename, "rb")
            return filename, fdesc
        else:
            name = getattr(filename, "name", "No name")
            return name, filename

    def next(self):
        try:
            pkt = None
            while pkt is None:
                pkt = self.read_packet()
        except EOFError:
            raise StopIteration

        return pkt

    __next__ = next

    def read_packet(self, size=0):
        line = self.f.readline().decode('ASCII').strip()

        if not line or len(line) == 0:
            raise EOFError

        match = re.match(PYTHON_CAN_LOGGER_FORMAT_PATTERN, line)
        if not match:
            return None

        t, idn, extended_flag, _, dl, data_str = match.groups()
        idn = int(idn, 16)
        data_bytes = bytearray.fromhex(data_str.replace(' ', '')) if data_str else bytearray()
        is_extended = bool(extended_flag)

        pkt = CAN(identifier=idn, data=data_bytes, flags='extended' if is_extended else '')

        return pkt

    def dispatch(self, callback):
        for p in self:
            callback(p)

    def read_all(self, count=-1):
        res = []
        while count != 0:
            try:
                p = self.read_packet()
                if p is None:
                    continue
            except EOFError:
                break
            count -= 1
            res.append(p)
        return PacketList(res, name=os.path.basename(self.filename))

    def recv(self, size=0):
        return self.read_packet()

    def fileno(self):
        return self.f.fileno()

    @property
    def closed(self):
        return self.f.closed

    def close(self):
        return self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tracback):
        self.close()

    @staticmethod
    def select(sockets, remain=None):
        return [s for s in sockets if isinstance(s, PythonCanLoggerReader) and
                not s.closed]


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
        "-q", "--silent", action="store_true", default=False, help="Silent mode"
    )
    parser.add_argument(
        "-f", "--file", type=str, required=False, help="read from a candump instead"
    )

    args = parser.parse_args()

    if args.file is not None:
        if is_python_can_logger_format(args.file):
            sock = PythonCanLoggerReader(args.file)
        else:
            sock = CandumpReader(args.file)

        interface_string = "log"
    else:
        sock, interface_string = create_socket(
            args.python_can_args, args.interface, args.channel, args.bitrate
        )

    pretty_iface_name = sanitize_string(interface_string)

    class PrintSink(Sink):
        def push(self, pkt):
            if not pkt.flags or "extended" not in pkt.flags:  # Check for standard frame
                print(f"({pkt.time:010.06f}) {pretty_iface_name} {pkt.identifier:03x}#{pkt.data.hex()}")
            else:  # Extended frame
                print(f"({pkt.time:010.06f}) {pretty_iface_name} {pkt.identifier:08x}#{pkt.data.hex()}")

            return

        def high_push(self, msg):
            return

    packet_count = 0
    feeder = CLIFeeder()
    wire = None
    if not args.silent:
        printer = PrintSink()
        feeder > printer
    if args.write is not None:
        wire = WrpcapSink(args.write)
        feeder > wire

    p = PipeEngine(feeder)
    p.start()

    def just_feed(pkt):
        nonlocal packet_count
        feeder.send(pkt)
        packet_count = packet_count + 1
        return
    sniff(opened_socket=sock, prn=just_feed, store=0)
    time.sleep(1.337)  # need to give PipeEngine time to write all packets out.
    feeder.close()

    sock.close()
    if wire:
        wire.f.flush()
    if p.thread.is_alive():
        p.stop()

    sys.stderr.write("processed %d packets\n" % packet_count)


if __name__ == "__main__":
    main()
