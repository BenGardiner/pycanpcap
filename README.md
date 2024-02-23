candump and write a pcap using scapy (and python-can)

```cmd.exe
 > python -m pip install pycanpcap
 > python -m pycanpcap.log -i cantact -c 0 -w can.pcap
WARNING: No libpcap provider available ! pcap won't be used
WARNING: Wireshark is installed, but cannot read manuf !
(000.008538) PythonCANSocket_cantact_0 007#0000b5f8
(000.008700) PythonCANSocket_cantact_0 01b#0000b5f8
(000.008961) PythonCANSocket_cantact_0 055#01025afc328e5b3e
(000.009318) PythonCANSocket_cantact_0 00f#f80fb5f831
(000.018648) PythonCANSocket_cantact_0 007#0000b6f8
(000.018834) PythonCANSocket_cantact_0 01b#0000b6f8
(000.019378) PythonCANSocket_cantact_0 00f#f90fb6f85a
^C
```

1. ignore the warnings on windows
2. Ctrl-C when ready
3. open can.pcap in wireshark
4. grep the output as usual