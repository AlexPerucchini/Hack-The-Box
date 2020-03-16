
<head>
<link rel="stylesheet" href="css/retro.css">
</head>

## HTB-Popcorn (10.10.10.6)
----
### Summary
![popcorn](images/popcorn_1.png)
----
### Scanning/Enumeration
---
#### nmap 
```
sudo nmap -T4 -A 10.10.10.6
Password:
Sorry, try again.
Password:
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-15 17:36 MDT
Nmap scan report for 10.10.10.6
Host is up (0.058s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/15%OT=22%CT=1%CU=41941%PV=Y%DS=2%DC=T%G=Y%TM=5E6EBC0
OS:0%P=x86_64-apple-darwin19.0.0)SEQ(SP=CE%GCD=1%ISR=D1%TI=Z%CI=Z%II=I%TS=8
OS:)OPS(O1=M54DST11NW6%O2=M54DST11NW6%O3=M54DNNT11NW6%O4=M54DST11NW6%O5=M54
OS:DST11NW6%O6=M54DST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0
OS:)ECN(R=Y%DF=Y%T=40%W=16D0%O=M54DNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+
OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M54DST11NW6
OS:%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN
OS:=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   55.72 ms 10.10.14.1
2   55.80 ms 10.10.10.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.92 seconds
```
#### nikto

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.6
+ Target Hostname:    10.10.10.6
+ Target Port:        80
+ Start Time:         2020-03-15 18:12:05 (GMT-6)
---------------------------------------------------------------------------
+ Server: Apache/2.2.12 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, inode: 43621, size: 177, mtime: Fri Mar 17 11:07:05 2017
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.2.12 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ Retrieved x-powered-by header: PHP/5.2.10-2ubuntu6.10
+ /test: Output from the phpinfo() function was found.
+ OSVDB-112004: /test: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).
+ OSVDB-112004: /test: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ /test.php?%3CSCRIPT%3Ealert('Vulnerable')%3C%2FSCRIPT%3E=x: Output from the phpinfo() function was found.
+ /test/: Output from the phpinfo() function was found.
+ OSVDB-3092: /test/: This might be interesting...
+ /test/jsp/buffer1.jsp: Output from the phpinfo() function was found.
+ /test/jsp/buffer2.jsp: Output from the phpinfo() function was found.
+ /test/jsp/buffer3.jsp: Output from the phpinfo() function was found.
+ /test/jsp/buffer4.jsp: Output from the phpinfo() function was found.
+ /test/jsp/declaration/IntegerOverflow.jsp: Output from the phpinfo() function was found.
+ /test/jsp/extends1.jsp: Output from the phpinfo() function was found.
+ /test/jsp/extends2.jsp: Output from the phpinfo() function was found.
+ /test/jsp/Language.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageAutoFlush.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageDouble.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageExtends.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageImport2.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageInfo.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageInvalid.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageIsErrorPage.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageIsThreadSafe.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageSession.jsp: Output from the phpinfo() function was found.
+ /test/realPath.jsp: Output from the phpinfo() function was found.
+ /test.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/phpinfo.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/phpinfo.php3: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/phpinfo.php3: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/test.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/test.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/info.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/index.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/index.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/php_info.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/php_info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /test.php: This might be interesting...
+ 8312 requests: 2 error(s) and 50 item(s) reported on remote host
+ End Time:           2020-03-15 18:21:32 (GMT-6) (567 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

#### gobuster
```

```

#### http
http://10.10.10.6/
![popcorn](images/popcorn_2.png)

http://10.10.10.6/test/
![http://10.10.10.6/test/](images/popcorn_3.png)

### Vulnerabilities
---

```
Apache mod_cgi - 'Shellshock' Remote Command Injection  | exploits/linux/remote/34900.py

```
### Exploits
---
