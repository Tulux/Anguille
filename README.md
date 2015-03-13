Anguille
========

Description
-----------

Anguille is a client/server program establishing dynamic UDP tunnel to carry TCP traffic. An instance must be running on a server and another one on a client. Particularity of this tunnel is its ability to change its own UDP ports while tunneling and so preventing filtering based on ports.

Why Anguille?
-------------

Today a lot of tunnelling systems are already existing (SSH, VPN, SSL-based, etc.) but are really easy to censor especially with TCP/UDP associated ports blocking.
In example, **some mobile ISPs are blocking TCP and UDP communications** which exceed an amount of time/bandwidth violating [neutrality principle](http://en.wikipedia.org/wiki/Net_neutrality) without contractually informing final user. There is other examples as totalitarian countries, airports hotspots, etc.
It technically can be achieved by sending RST packets (TCP communications only) then setting automated temporary firewall rule or by various ways associated to [DPI](http://en.wikipedia.org/wiki/Deep_packet_inspection).

The idea with this project is to offer a way to override these limitations. Indeed, this tunnel is much difficult to block and stop because it forgets port concept, moreover its layer 4 protocol (UDP) is more difficult to trace and stop than TCP because this is harder to make differences between UDP streams than between TCP streams.

***Warning!***

A design breach is actually present: a TCP stream is used to manage tunnel so it is technically possible to block TCP port and so prevent management (obviously, tunnel can't be created without management packets). Actually this is volountary because it was the fastest way to develop the whole program. The real behaviour is to create another UDP tunnel and reimplemente TCP concepts as reordering, integrity etc. but I don't have enough time for now.
This design breach is not a major problem because these TCP sessions are very shorts (some bytes only) and shouldn't be blocked by firewalls.

How does it work?
-----------------

[PUT SCHEME HERE]

Requirements
------------

- OS: Linux, BSD or any Posix-compliant system (please forget Windows)
- iptables
- **root** access
- Server-side: some open ports (see below)

Root access is required because of raw sockets. I guess this right may be granted by using FS extensions and executing setcap but honestly I've not tested it yet. Root access is also required due to adding (and deleting) one iptables rule preventing TCP/IP stack to send RST packets to local programs (see scheme). Obviously, iptables rule can permanently be configured by hand without program syscall.

If you are afraid about running program in root mode, I let you look for any dangerous systemcall into the source code ;)

On server side, some ports must be opened:
* TCP port used to manage tunnel
* UDP range that you want to use

Example
-------

1) Configure server<br>
TCP/9870 opened<br>
UDP/4500 to UDP/4600 opened

2) Run this command on the server<br>
`./anguille -v 1 -r 4500:4600 -t 22 -p MY_PASS_123 -m 9870 -s`

3) Configure client<br>
Be sure that UDP/6200 to UDP/6300 are not used (bound) by anything else. If you don't have any particular services, theses ports should be free.

4) Run this command on the client<br>
`./anguille -v 1 -r 6200:6300 -t 1234 -p MY_PASS_123 -m 9870 -i SERVER_IP`

5) On client side, TCP traffic to TCP/1234 will be translated to the server on TCP/22.<br>
You can test it by running this command:<br>
`ssh -p 1234 127.0.0.1`<br>
You get a server shell.
