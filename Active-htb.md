
<head>
   <link rel="stylesheet" href="css/retro.css">
</head>

## HTB-Active (10.10.10.100)
----
### Summary
![Bastard](images/active.png)

Additonal resources/reading:
* [Group Policy Pwnage](https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/)
* Official Course walkthrough: https://www.udemy.com/course/practical-ethical-hacking/learn/lecture/17282948#content


---
### Scanning/Enumeration
---
#### nmap 
```Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 06:06 MST
Nmap scan report for 10.10.10.100
Host is up (0.059s latency).
Not shown: 983 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-02-28 13:08:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/28%OT=53%CT=1%CU=37406%PV=Y%DS=2%DC=T%G=Y%TM=5E59111
OS:3%P=x86_64-apple-darwin19.0.0)SEQ(SP=104%GCD=1%ISR=108%TI=I%CI=I%II=I%SS
OS:=S%TS=7)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11
OS:%O5=M54DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%
OS:W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%
OS:O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=8
OS:0%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%
OS:Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=
OS:Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m12s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-02-28T13:09:45
|_  start_date: 2020-02-28T13:07:29

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   63.60 ms 10.10.14.1
2   57.65 ms 10.10.10.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 209.76 seconds
```

### Vulnerabilities

List of potential vulnerabilites to consider:
```
searchsploit windows 2008 r2 
--------------------------------------------------------- -----------------------------------------------
 Exploit Title                                           |  Path
                                                         | (/usr/local/opt/exploitdb/share/exploitdb/)
--------------------------------------------------------- -----------------------------------------------
Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64) - Lo | exploits/windows/local/39719.ps1
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote C | exploits/windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'Etern | exploits/windows/remote/42315.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' | exploits/windows_x86-64/remote/41987.py
--------------------------------------------------------- -----------------------------------------------
```
```
--------------------------------------------------------- ------------------------------------------------
 Exploit Title                                           |  Path
                                                         | (/usr/local/opt/exploitdb/share/exploitdb/)
--------------------------------------------------------- ------------------------------------------------
Microsoft DNS RPC Service - 'extractQuotedChar()' Remote | exploits/windows/remote/16366.rb
Microsoft DNS RPC Service - 'extractQuotedChar()' TCP Ov | exploits/windows/remote/16748.rb
Microsoft RPC DCOM Interface - Remote Overflow (MS03-026 | exploits/windows/remote/16749.rb
Microsoft Windows - 'Lsasrv.dll' RPC Remote Buffer Overf | exploits/windows/remote/293.c
Microsoft Windows - 'RPC DCOM' Long Filename Overflow (M | exploits/windows/remote/100.c
Microsoft Windows - 'RPC DCOM' Remote (1)                | exploits/windows/remote/69.c
Microsoft Windows - 'RPC DCOM' Remote (2)                | exploits/windows/remote/70.c
Microsoft Windows - 'RPC DCOM' Remote (Universal)        | exploits/windows/remote/76.c
Microsoft Windows - 'RPC DCOM' Remote Buffer Overflow    | exploits/windows/remote/64.c
Microsoft Windows - 'RPC DCOM' Scanner (MS03-039)        | exploits/windows/remote/97.c
Microsoft Windows - 'RPC DCOM2' Remote (MS03-039)        | exploits/windows/remote/103.c
Microsoft Windows - DCOM RPC Interface Buffer Overrun    | exploits/windows/remote/22917.txt
Microsoft Windows - DNS RPC Remote Buffer Overflow (2)   | exploits/windows/remote/3746.txt
Microsoft Windows - Net-NTLMv2 Reflection DCOM/RPC (Meta | exploits/windows/local/45562.rb
```

---

### Exploits 
---

#### 1. Get a shell on the target system. Let's focus on SMB2 port 445 by connecting via smbclient
```
sudo smbclient -L \\\\10.10.10.100\\
Enter WORKGROUP\root's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
```
After trying to connect to the different shares, Replication is the only one with anonymous logi
```

```

```
~/Documents/code/scratch$ sudo smbclient \\\\10.10.10.100\\Replication\\
Enter WORKGROUP\root's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloByte
s/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as GPE.INI (0.5 KiloBytes/sec) (averag
e 0.3 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as GptTmp
l.inf (4.1 KiloBytes/sec) (average 1.6 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (1.9 Ki
loBytes/sec) (average 1.7 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as Registry.pol (10.5 KiloBytes/sec) 
(average 3.5 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as GPT.INI (0.1 KiloBytes/sec) (average 2.9 KiloByte
s/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as GptTmp
l.inf (14.5 KiloBytes/sec) (average 4.6 KiloBytes/sec)
```

