---
sticker: emoji//1f37d-fe0f
---
# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |
| 8080 | http    |

Let's start reconnaissance.

# RECONNAISSANCE
---

We have two websites, let's visit them both

### Port 80
---

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250111142532.png)

Source code is normal too, let's visit the other one.

### Port 8080
---

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250111142600.png)

Weird, if we watch the source code, we can see the following:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250111142812.png)
So, I think fuzzing in both websites would be useful in this case, let's proceed.


## Fuzzing
----

### 80
---

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250111142908.png)

We got `assets` and `images`, if we visit them, we get status code `403`, which means we don't have enough permissions to read them. Let's fuzz other port

### 8080
----

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250111143018.png)


Once we visit `/website`, this happens:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250111143118.png)

Tried fuzzing but nothing useful came from it, let's visit `/console`

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250111144530.png)

We get a redirect but nothing else.


That's when I knew I needed a different approach, so, I went back to the site on port 80 and explored further:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153001.png)

If we go to `/contact`, we can see something interesting written on there, it is talking about something called `silverpeas` and it gives us an username: `scr1ptkiddy`, after a research, I found the following: 

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153158.png)

Silverpeas usually runs on port 8080, let's check if that's the case for this machine:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153247.png)

That's right, let's begin exploitation.


# EXPLOITATION
---

We already know we have `silverpeas` running on port 8080, let's search any sort of exploit to bypass the login panel:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153358.png)

Found this GitHub page which talks about `Authentication Bypass` in the `silverpeas` CRM, let's check the PoC:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153444.png)

Let's fire up burp and try:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153608.png)

Let's follow the PoC and delete the password field:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153636.png)

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153653.png)

We get a GET request, let's forward:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153801.png)

We got in, time to explore:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113154552.png)


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113153844.png)

Found an unread notification, if we read it, we find there's 2 more users: `Manager` and `Administrateur` let's log into both accounts following the same PoC from earlier:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113154718.png)

In `Manager`, we find ssh credentials:

```ad-note

#### Credentials
----

`tim`:`cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol`

```

We are unable to log into `Administrateur` account using the same method, but we don't need to, let's log into ssh:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113154929.png)

```ad-important
 User: `THM{c4ca4238a0b923820dcc509a6f75849b}`
```

Time to start with privilege escalation.

# PRIVILEGE ESCALATION
---

We already have initial access on Tim's account, let's use linpeas to enumerate possible PE vectors:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113162507.png)


`Tim`is part of the `adm` group, let's check that:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113162540.png)

It is indeed right, let's check `/etc/passwd`:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113162609.png)

We have another user, `tyler`, we can perform the following:

```ad-hint
1. grep -Ri 'password' /var/log 2>/dev/null
2. Check for any password regarding `tyler` user
3. Switch user to `tyler`

#### Output
---

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113162806.png)

We are able to see we got a password: `_Zd_zx7N823/`, let's switch:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113162843.png)

```

Nice, we got a shell as `tyler`, let's check the sudo permissions:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113162921.png)

Lucky, we can just perform `sudo bash -p` and get a root as shell:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113162947.png)

Just like that, CTF is done:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250113163008.png)

```ad-important
Root: `THM{098f6bcd4621d373cade4e832627b4f6}`
```

