# StealthPing

<b>Usage:</b> stealthping.py [-h] [-sP] [-sA] [-sO] [-p] [--top-ports] [--nat] [-m]
                      [-i INTERFACE] [-C] -t TARGET

<b>optional arguments:</b><br>
  -h, --help            show this help message and exit<br>
  -sP                   single Ping<br>
  -sA                   Scan all ports<br>
  -sO                   Detect the operative system with the TTL value<br>
  -p, --port            Set the port range<br>
  --top-ports           Scan the most common ports<br>
  --nat                 Detect nated ports<br>
  -m, --macchange       Change randomly the mac<br>
  -i INTERFACE, --interface INTERFACE<br>
                        Set the interface<br>
  -C, --capture         Capture the TCP network traffic to specific IP<br>
  -t TARGET, --target TARGET<br>
                        Target IP<br>

