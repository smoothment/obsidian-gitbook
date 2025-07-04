# MISGUIDED GHOSTS

## PORT SCAN

***

| PORT | SERVICE |
| ---- | ------- |
| 21   | FTP     |
| 22   | SSH     |

## RECONNAISSANCE

***

Ftp anonymous login is enabled, let's check it up:



```bash
ftp 10.10.20.176
Connected to 10.10.20.176.
220 (vsFTPd 3.0.3)
Name (10.10.20.176:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10166|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 28  2020 pub
226 Directory send OK.

ftp> cd pub
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||7796|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           103 Aug 28  2020 info.txt
-rw-r--r--    1 ftp      ftp           248 Aug 26  2020 jokes.txt
-rw-r--r--    1 ftp      ftp        737512 Aug 18  2020 trace.pcapng
226 Directory send OK.
ftp> mget *
mget info.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||60019|)
150 Opening BINARY mode data connection for info.txt (103 bytes).
100% |*****************************************************************************************************************************************|   103        1.07 KiB/s    00:00 ETA
226 Transfer complete.
103 bytes received in 00:00 (0.38 KiB/s)
mget jokes.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||63356|)
150 Opening BINARY mode data connection for jokes.txt (248 bytes).
100% |*****************************************************************************************************************************************|   248        2.92 KiB/s    00:00 ETA
226 Transfer complete.
248 bytes received in 00:00 (0.96 KiB/s)
mget trace.pcapng [anpqy?]? y
229 Entering Extended Passive Mode (|||52708|)
150 Opening BINARY mode data connection for trace.pcapng (737512 bytes).
100% |*****************************************************************************************************************************************|   720 KiB  511.72 KiB/s    00:00 ETA
226 Transfer complete.
737512 bytes received in 00:01 (455.66 KiB/s)

```

As seen, we are able to get some files, let's take a look at them:

```bash
cat info.txt; cat jokes.txt
I have included all the network info you requested, along with some of my favourite jokes.

- Paramore

Taylor: Knock, knock.
Josh:   Who's there?
Taylor: The interrupting cow.
Josh:   The interrupting cow--
Taylor: Moo

Josh:   Knock, knock.
Taylor: Who's there?
Josh:   Adore.
Taylor: Adore who?
Josh:   Adore is between you and I so please open up!
```

There is a hint on the `jokes.txt`  file as it hints on `port knocking`,  Port knocking is a stealthy method used to open closed ports on a firewall by sending a specific sequence of connection attempts (knocks) to predefined ports. These ports appear closed from the outside, but when the correct sequence is received, the firewall temporarily opens a port (e.g., SSH) for the client. It’s like a secret handshake, only those who know the right knock pattern can get in. This technique adds an extra layer of obscurity and is often used to hide services from unauthorized users.

Check more info on `port knocking` below:

{% embed url="https://www.packetlabs.net/posts/what-is-port-knocking/" %}

Based on the info file, we have all the network info needed on the `trace.pcapng` file, let's take a look at it, we can use wireshark for it:

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption><p>Wireshark</p></figcaption></figure>

We can see some TCP requests being made to:

```
192.168.236.131
```

Let's try to filter by this ip with:

```
ip.addr == 192.168.236.131
```

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>













