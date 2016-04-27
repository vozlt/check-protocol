TCP/IP based applicaction protocol checker
==========

[![License](http://img.shields.io/badge/license-BSD3-brightgreen.svg)](https://tldrlegal.com/license/bsd-3-clause-license-%28revised%29)

This checker has some simple sources to check the TCP/IP based application protocols. 

## Dependencies
* gcc

## Installation

```
shell> make
```

```
cc -Wall -O2    icmp_status.c   -o icmp_status
cc -Wall -O2    icmp_traceroute.c   -o icmp_traceroute
cc -Wall -O2    smtp_status.c   -o smtp_status
cc -Wall -O2    sntp_status.c   -o sntp_status
cc -Wall -O2    tftp_status.c   -o tftp_status
```

## Running

##### ICMP:PING

```
shell> ./icmp_status google-public-dns-a.google.com
```

```
reply to   : 8.8.8.8
icmp_type  : 0x8
icmp_code  : 0x0
icmp_cksum : 0x8ca6
icmp_id    : 0x7342
icmp_seq   : 0xf
send packet: 08 00 a6 8c 42 73 0f 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00

reply from : 8.8.8.8
icmp_type  : 0x0
icmp_code  : 0x0
icmp_cksum : 0x8cae
icmp_id    : 0x7342
icmp_seq   : 0xf
icmp_data  :
icmp packet: 00 00 ae 8c 42 73 0f 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00
recv packet: 45 00 00 30 00 00 00 00 31 01 02 16 08 08 08 08 80
c7 f6 e0 00 00 ae 8c 42 73 0f 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00


ICMP SERVER STATUS : OK
```

##### ICMP:TRACEROUTE

```
shell> ./icmp_traceroute google-public-dns-a.google.com
```

```
traceroute to (8.8.8.8), 30 hops max

 1 128.199.191.253
 2 103.253.144.241
 3 103.253.144.250
 4 80.239.133.57
 5 62.115.13.238
 6 209.85.243.158
 7 64.233.174.109
 8 * * *
 9 8.8.8.8

TRACEROUTE TO 8.8.8.8: OK
```

##### SMTP

```
shell> ./smtp_status mx1.hotmail.com sender@smtp.localhost receiver@hotmail.com
```

```
<<< 220 SNT0-MC3-F19.Snt0.hotmail.com Sending unsolicited commercial or
bulk e-mail to Microsoft's computer network is prohibited.

>>> HELO mx1.hotmail.com

<<< 250 SNT0-MC3-F19.Snt0.hotmail.com (3.19.0.77) Hello [61.72.251.55]

>>> MAIL FROM: sender@smtp.localhost

<<< 250 sender@smtp.localhost....Sender OK

>>> RCPT TO: receiver@hotmail.com

<<< 250 receiver@hotmail.com

>>> DATA

<<< 354 Start mail input; end with <CRLF>.<CRLF>

>>> Subject: SMTP PROTOCOL TESTING
DATA SECTION
.

<<< 250 <SNT0-MC3-F1964xSNUX00142e45@SNT0-MC3-F19.Snt0.hotmail.com>
Queued mail for delivery

>>> QUIT

<<< 221 SNT0-MC3-F19.Snt0.hotmail.com Service closing transmission channel

SMTP SERVER STATUS : OK
```

##### SNTP

```
shell> ./sntp_status pool.ntp.org
```

```
server               : pool.ntp.org
server port          : 123
my bind port         : 40846

send packet size     : 48
send packet          : e3 00 04 00 00 00 00 00 00 00 00 00 37 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00
li_vn_mode           : 227 / LI: 3, VN: 4, MODE : 3
Stratum              : 00
Poll                 : 04
Precision            : 00
Root Delay           : 00
Root Dispersion      : 00
Reference Identifier : 37
Reference Timestamp  : 00
Originate Timestamp  : 00
Receive Timestamp    : 00
Transmit Timestamp   : 00
Reference Time       : 2036/02/07 15:28:16
Originate Time       : 2036/02/07 15:28:16
Receive Time         : 2036/02/07 15:28:16
Transmit Time        : 2036/02/07 15:28:16

recv packet size     : 48
recv packet          : 24 02 04 ec 00 00 27 00 00 00 05 6c cc 7b 02 05 d7
71 bc 67 f9 f3 61 60 00 00 00 00 00 00 00 00 d7 71 bd 40 de 13 5d 04 d7
71 bd 40 de 13 e3 00
li_vn_mode           : 36 / LI: 0, VN: 4, MODE : 4
Stratum              : 02
Poll                 : 04
Precision            : -20
Root Delay           : 270000
Root Dispersion      : 6c050000
Reference Identifier : 5027bcc
Reference Timestamp  : 6061f3f967bc71d7
Originate Timestamp  : 00
Receive Timestamp    : 45d13de40bd71d7
Transmit Timestamp   : e313de40bd71d7
Reference Time       : 2014/07/17 12:07:19
Originate Time       : 2036/02/07 15:28:16
Receive Time         : 2014/07/17 12:10:56
Transmit Time        : 2014/07/17 12:10:56

send packet size     : 48
send packet          : e3 00 04 fa 00 01 00 00 00 01 00 00 cc 7b 02 05 d7
71 bd 40 de 13 e3 00 d7 71 bd 40 de 13 e3 00 d7 71 bd 40 de 13 5d 04 d7
71 bd 40 de 13 e3 00
li_vn_mode           : 227 / LI: 3, VN: 4, MODE : 3
Stratum              : 00
Poll                 : 04
Precision            : -6
Root Delay           : 100
Root Dispersion      : 100
Reference Identifier : 5027bcc
Reference Timestamp  : e313de40bd71d7
Originate Timestamp  : e313de40bd71d7
Receive Timestamp    : 45d13de40bd71d7
Transmit Timestamp   : e313de40bd71d7
Reference Time       : 2014/07/17 12:10:56
Originate Time       : 2014/07/17 12:10:56
Receive Time         : 2014/07/17 12:10:56
Transmit Time        : 2014/07/17 12:10:56

recv packet size     : 48
recv packet          : 24 02 04 ec 00 00 27 00 00 00 05 6c cc 7b 02 05 d7
71 bc 67 f9 f3 61 60 d7 71 bd 40 de 13 e3 00 d7 71 bd 40 de 6d 74 ad d7
71 bd 40 de 6d fd 20
li_vn_mode           : 36 / LI: 0, VN: 4, MODE : 4
Stratum              : 02
Poll                 : 04
Precision            : -20
Root Delay           : 270000
Root Dispersion      : 6c050000
Reference Identifier : 5027bcc
Reference Timestamp  : 6061f3f967bc71d7
Originate Timestamp  : e313de40bd71d7
Receive Timestamp    : ad746dde40bd71d7
Transmit Timestamp   : 20fd6dde40bd71d7
Reference Time       : 2014/07/17 12:07:19
Originate Time       : 2014/07/17 12:10:56
Receive Time         : 2014/07/17 12:10:56
Transmit Time        : 2014/07/17 12:10:56

NTPD SERVER STATUS  : OK
```

##### TFTP

```
shell> ./tftp_status tftp.localhost
```

```
server           : tftp.localhost
server port      : 69
my bind port     : 33451
send packet size : 17
send packet      : 00 01 76 30 7a 6c 74 00 6e 65 74 61 73 63 69 69 00
                   00 01 v  0  z  l  t  00 n  e  t  a  s  c  i  i  00
recv packet size : 19
recv packet      : 00 05 00 01 46 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 00
                   00 05 00 01 F  i  l  e     n  o  t     f  o  u  n  d  00
th_opcode        : 5
th_block         : 1
th_data          : File not found
TFTPD SERVER STATUS : OK
```

## Author
YoungJoo.Kim(김영주) [<vozltx@gmail.com>]
