---
sticker: emoji//1f3b5
---

# LO-FI

## ENUMERATION

***

### OPEN PORTS

***

| PORT | SERVICE |
| ---- | ------- |
| 22   | ssh     |
| 80   | http    |

## RECONNAISSANCE

***

This is the first thing we see once we go to the website:

![](gitbook/cybersecurity/images/Pasted%20image%2020250120153845.png)

We have a search bar, my first guess would be we need to test either for \[\[CYBERSECURITY/Bug Bounty/Vulnerabilities/SERVER SIDE VULNERABILITIES/INJECTIONS/SQLI/SQL INJECTION (SQLI).md|SQLI]], \[\[CYBERSECURITY/Bug Bounty/Vulnerabilities/SERVER SIDE VULNERABILITIES/CROSS SITE SCRIPTING/CROSS SITE SCRIPTING (XSS).md|XSS]] or \[\[CYBERSECURITY/Bug Bounty/Vulnerabilities/SERVER SIDE VULNERABILITIES/FILE INCLUSION VULNERABILITIES/LOCAL FILE INCLUSION (LFI).md|LFI]], let's check:

![](gitbook/cybersecurity/images/Pasted%20image%2020250120154118.png)

XSS does not work, let's test SQLI:

![](gitbook/cybersecurity/images/Pasted%20image%2020250120154142.png)

Seems like SQLI does not work too, if we check around the page, we find a `relax` section, if we click on it, the following URL appears:

![](gitbook/cybersecurity/images/Pasted%20image%2020250120154358.png)

So, we can check it is indeed reading from a file called: `relax.php`, if we try LFI, we get the following:

![](gitbook/cybersecurity/images/Pasted%20image%2020250120154434.png)

LFI is possible, let's begin exploitation.

## EXPLOITATION

***

Nice, so we already know we can use LFI to retrieve the contents of a file, since our main purpose is to read `flag.txt`, we only need to write: `../../../flag.txt` in order to read the file:

![](gitbook/cybersecurity/images/Pasted%20image%2020250120154645.png)

Just like that room is done, no need to reach root.
