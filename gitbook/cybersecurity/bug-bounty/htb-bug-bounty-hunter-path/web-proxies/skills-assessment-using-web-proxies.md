---
sticker: emoji//1f525
---

# Skills Assessment - Using Web Proxies

We are performing internal penetration testing for a local company. As you come across their internal web applications, you are presented with different situations where Burp/ZAP may be helpful. Read each of the scenarios in the questions below, and determine the features that would be the most useful for each case. Then, use it to help you in reaching the specified goal.

## Questions

***

![](gitbook/cybersecurity/images/Pasted%20image%2020250124140539.png)

### 1

***

Let's visit the site first and send a request to burp:

![](gitbook/cybersecurity/images/Pasted%20image%2020250124140718.png)

![](gitbook/cybersecurity/images/Pasted%20image%2020250124141130.png)

What we need to do is the following:

```ad-summary
1. Do intercept -> Response to this request.
2. Change getflag value to enabled: ![](gitbook/cybersecurity/images/Pasted%252520image%25252020250124141225.png)
3. Forward the request.
4. Turn off proxy, wait for the page to load and turn intercept again.
5. Click on the button, and intercept the POST request.
6. Send POST request to repeater and send 10 requests.
7. Get flag.
```

If we follow those steps, we get the following:

![](gitbook/cybersecurity/images/Pasted%20image%2020250124141428.png)

Flag would be: `HTB{d154bl3d_bu770n5_w0n7_570p_m3}`

### 2

***

Let's visit `/admin.php` and intercept the request:

![](gitbook/cybersecurity/images/Pasted%20image%2020250124141615.png)

We can use CyberChef for this:

![](gitbook/cybersecurity/images/Pasted%20image%2020250124141735.png)

## 3

***

It is a MD5 hash but if we look closely, it is missing a character, we need to fuzz, send the request to intruder and do the following:

![](gitbook/cybersecurity/images/Pasted%20image%2020250124141933.png)

Add the `alphanum-case.txt` dictionary with these encoding options, we need to do `Base64 Encode` and `Encode as ASCII hex` since this is the way the cookie is encoded in first place.

![](gitbook/cybersecurity/images/Pasted%20image%2020250124142952.png)

Now, if we filter by length and check responses, we can see the following:

![](gitbook/cybersecurity/images/Pasted%20image%2020250124143255.png)

There it is, flag is: `HTB{burp_1n7rud3r_n1nj4!}`

## 4

***

Let's use the module:

![](gitbook/cybersecurity/images/Pasted%20image%2020250124143624.png)

Once we send exploit, we can see that the endpoint is: `CFIDE`

Just like that, everything is done!
