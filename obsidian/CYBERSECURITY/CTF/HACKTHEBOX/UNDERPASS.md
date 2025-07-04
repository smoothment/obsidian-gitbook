---
sticker: emoji//1f3ce-fe0f
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |



# RECONNAISSANCE
---


Let's go into the website:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120155437.png)

Simple apache2 webpage, source code seems normal too, fuzzing does not bring anything useful, there's something else we need to enumerate.

Since I already checked for TCP ports, let's do some UDP port check:


`sudo nmap -sU --top-ports 100 10.10.11.48`


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120155642.png)

There it is, we had ports open on UDP, so, the open ports table would actually be:



| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |
| 161  | snmp    |
| 1812 | radius  |
| 1813 | raddact |
If we check on the internet about SNMP, we find the following:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120155817.png)

It could be useful trying to enumerate this protocol, to our luck, Metasploit can help us with it:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120155941.png)


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120160017.png)

So, we find about something called `Daloradius` 

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120160052.png)

Let's add `underpass.htb` to `/etc/hosts`:

`echo '10.10.11.48 underpass.htb' | sudo tee -a /etc/hosts`


If we go back to the website and search for the `daloradius` directory, we find this:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120160325.png)

I think we need to fuzz, let's begin exploitation.



# EXPLOITATION
---

In order to fuzz, let's use [dirsearch](https://github.com/maurosoria/dirsearch):


```ad-hint
#### Used dirsearch commands
---

`dirsearch -u "http://underpass.htb/daloradius/" -t 50`

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120160709.png)

We found something important `/app`, let's try to fuzz for that:

`dirsearch -u "http://underpass.htb/daloradius/app" -t 50`

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120160853.png)

```


We found a login page, let's check it out:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120160957.png)

We can try `SQLI` and check if we're lucky:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161050.png)

What about default credentials?:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161124.png)


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161142.png)


Still no luck, let's try to fuzz a bit more to check if we miss something useful, let's change our wordlist too:

`dirsearch -u "http://underpass.htb/daloradius/app" -t 50 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt`

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161314.png)

We found something new `/operators`, let's check it out:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161421.png)

This is a different login page than the other one, let's try default creds:


`administrator`:`radius`


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161500.png)

Nice, we got access, let's look around:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161530.png)

In the users section, we find the following, an user called `svcMosh` and a password that is hashed, let's decrypt that:
![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161644.png)

We got credentials finally:

```ad-important
`svcMosh`:`underwaterfriends`
```

Let's log in using ssh:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161747.png)

Now we can read `user.txt`:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161803.png)

```ad-important
User: `49e125d2a39790c0c0ce8593bb14b103`
```

Let's start PRIVESC

# PRIVILEGE ESCALATION
---


We can check our sudo privileges first:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161903.png)

We have sudo permissions on some binary called `mosh-server`

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120161956.png)

Let's search for anything related on how to exploit this to get a root session:

```ad-summary

We can do the following in order to get a root shell:

1. `sudo /usr/bin/mosh-server`
2. Grab the key it generates in a format like the following: `MOSH CONNECT 60003 qgp88e1LYG5KFwRgoCjJtQ`
3. `MOSH_KEY=Key we got, in this case qgp88e1LYG5KFwRgoCjJtQ mosh-client 127.0.0.1 port we got, in this case 60003`
4. Get the root session.



```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120162643.png)

Let's read `root.txt`:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120162658.png)

```ad-important
Root: `33b5ffcbd7913b1b7a369ebe6843e711`
```

Just like that, machine is done!

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250120162731.png)

