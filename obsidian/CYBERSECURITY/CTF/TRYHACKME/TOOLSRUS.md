---
sticker: emoji//1f9f0
---

# ENUMERATION
---

## OPEN PORTS
---

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119144825.png)

| PORT | STATE | SERVICE |
| :--- | :---- | :------ |
| 22   | open  | ssh     |
| 80   | open  | http    |
| 1234 | open  | http    |
| 8009 | open  | ajp13   |

Have 4 open ports, 2 web applications, 1 ssh and another service known as `ajp13`, which basically is:

```ad-note

AJP is a wire protocol. It an optimized version of the HTTP protocol to allow a standalone web server such as [Apache](http://httpd.apache.org/) to talk to Tomcat. Historically, Apache has been much faster than Tomcat at serving static content. The idea is to let Apache serve the static content when possible, but proxy the request to Tomcat for Tomcat related content.

```

Knowing all this, let's proceed with the fuzzing of both websites.

## FUZZING
---

### Port 80


![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119150643.png)

Simple server, page source ain't have anything useful, let's fuzz:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119150835.png)

```ad-hint

#### Found

- `/guidelines`
- `/protected`

#### `/guidelines`

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119150923.png)

Found something useful, seems like a username, let's save it: `bob`

#### `/protected`

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119151214.png)

Login page, seems like we need to brute force the login with hydra, let's leave that for the reconnaissance.

```
### Port 1234

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119150045.png)

Seems like a simple Apache Tomcat, let's fuzz it

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119145958.png)

```ad-hint

#### Found

 - `/docs`
 - `/examples`
 - `/manager`

Let's explore them

#### `/docs`

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119150200.png)

Nothing useful.

#### `/examples`

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119150228.png)

#### `/manager`

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119150412.png)

A prompt asking for credentials is asked in order to log in the site.
```



# RECONNAISSANCE
---

Now, we already know we need to brute force the login page using hydra, for that, we need to perform the following scan:

```ad-hint

#### Command
----

`hydra -l bob -P /usr/share/wordlists/rockyou.txt -f {target_ip} http-get /{the_protected_url} -t 4 -V`

So, for this machine, command would be the following:

`hydra -l bob -P /usr/share/wordlists/rockyou.txt -f 10.10.83.182 http-get /protected -t 4 -V`

#### Output
---

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119151849.png)

We got our user and password

#### Credentials
----

`bob`: `bubbles`
```

Once we log into the website, this is shown:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119152106.png)

So, we need to move forward with the other port, `1234`, room tells us to use `nikto` and perform another scan in this port using the credentials we found, so, command would be the following:

```ad-hint

#### Command
----

`nikto -id {username_found}:{password_found} -h http://{target_ip}:1234/manager/html`

So, for this case, command would be:

`nikto -id bob:bubbles -h http://10.10.83.182:1234/manager/html`

#### Output
----

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119153501.png)

Found five documentation files, also, we need to scan for the server version, for this, let's use nmap:

#### Nmap
---

`nmap -sV -T4 -A -vv {IP}`

#### Output Scan
---

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119153846.png)
Server is running a `apache/2.4.18`, let's look for anything in metasploit

```


# EXPLOITATION
---

```ad-hint
#### Metasploit
----

Lets search for the following query in msfconsole: `search tomcat`

This brings up a lot of output, but the most interesting one is this:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119154236.png)
An Apache Tomcat Manager Authenticated Upload Code Execution, this seems perfect in order to get a shell, let's choose it:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119154932.png)
Let's enter the needed options:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119155028.png)

And, send the payload:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119155049.png)

We got a shell!

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119155132.png)

We got a shell as root!
```







# PRIVILEGE ESCALATION
---


Since we got a shell as root, there's no need to perform a privilege escalation, let's get our flag and finish the CTF:

```ad-note

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241119155246.png)

`flag`: `ff1fc4a81affcc7688cf89ae7dc6e0e1`
```

