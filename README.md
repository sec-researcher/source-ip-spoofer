# Spoof Source IP

Tool to play with spoofing the source IP on a UDP datagram.  It's written
in rust using the pnet library.

## Installation

#### Permissions
`source-ip-spoofer` creates raw packets which requires special permissions. If
you don't wish to use `sudo` or run `source-ip-spoofer` as root, you can
assign the needed capability directly to the executable on Linux
systems:
```
$ sudo setcap 'CAP_NET_RAW+eip' ./source-ip-spoofer
```

#### Download/install
Install `source-ip-spoofer`:
```
$ git clone https://github.com/sec-researcher/source-ip-spoofer.git
```

## source ip spoofer

`source-ip-spoofer` injects a UDP packet at the Ethernet frame level on the interface
specified by as first argument.  For `source-ip-spoofer` to work, the
destination MAC needs to be different from the MAC address of the interface
performing the injection.  Either use 2 hosts, or a single host with
multiple interfaces (e.g. a host with both wired and wireless interfaces).

You cannot use the loopback interface for testing, as the loopback
interface operates above the ethernet frame level and has no MAC address.

The source MAC and source IP are both spoofable.


```
$ ./source-ip-spoofer enp4s0 192.168.10.10 192.168.20.20  11000 389  00:eb:d5:43:de:60 AAAA01000001000000000000076578616d706c6503636f6d0000010001
Usage:
      enp4s0              Network interface for packet injection
      192.168.10.10       Sending address in the IP header
      192.168.20.20       Destination IP address
      11000               UDP Source port
      389                 Destination port
      00:eb:d5:43:de:60   MAC address in the Ethernet frame source
      AAAA01000001000000000000076578616d706c6503636f6d0000010001    payload in hex(This is a simple ldap query)
```

### Full example: Receive ldap response on different host than request

Start the nc on a 2nd host which will receive a ldap
response from target server(192.168.20.20):
```
host2$ nc -nlvp 11000
```

If we sent request to an external host the app will work in most cases 
if sender&reciever(spoofed) are sitting behind a NAT firewall.The source IP will be
replaced by the NAT router's IP before the query is sent to external host.
When external host sends the response, the NAT router will forward it to
the forged source IP of the original request.
