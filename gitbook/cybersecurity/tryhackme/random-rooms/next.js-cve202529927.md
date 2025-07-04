---
aliases:
  - 'Next.js: CVE-2025-29927'
---

# Next.js CVE-2025-29927

## Introduction

***

Next.js is a web development framework developed by Vercel to simplify the creation of high-performance web applications. Built on top of React, Next.js extends React’s capabilities by adding several features, such as static site generation (SSG) and server-side rendering (SSR). SSG pre-generates pages at build time, allowing faster delivery to users; moreover, SSR renders pages at request time, reducing load time. In brief, Next.js added features to improve performance and user experience.

[CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927), a recent vulnerability discovered by [Rachid and Yasser Allam](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware) in Next.js, revealed that it is possible to bypass authorisation checks if they occur in middleware. Middleware is the part that grants developers control over incoming requests. It acts as a bridge between the incoming request and the routing system. The routing system is file-based, i.e., routes are created and managed by organising files and directories. This vulnerability allows attackers to bypass middleware-based authorisation, and all versions before 14.2.25 and 15.2.3 are prone to this vulnerability.

Next.js is widely used across various types of applications, including e-commerce platforms, news apps, documentation sites, and interactive web apps. Consequently, this vulnerability can have dire consequences and requires administrators to upgrade their installations to a patched version.

In this room, we will explore how to exploit and detect this vulnerability.

## Exploitation

***

A proof of concept (PoC) [exploitable app](https://github.com/aydinnyunus/CVE-2025-29927) and exploit code are published by Yunus Aydin on GitHub. We have adapted the app and hosted it on the attached VM. You can view the sample web application by visiting `http://MACHINE_IP:3000` on the AttackBox. However, if you try to access the protected route at `http://MACHINE_IP:3000/protected`, you will be redirected to the home page.

### Curl

Exploiting the CVE-2025-29927 vulnerability is quite simple; all the attacker needs to do is add the extra HTTP header `x-middleware-subrequest: middleware` in their request. As explained in the [original post](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware) disclosing this vulnerability, the addition of the `x-middleware-subrequest` header leads to the request getting forwarded to its destination without the middleware manipulating it. Consequently, one does not need more than using `curl` with the proper header argument to access protected routes, i.e., pages.

Exploiting this vulnerability allows us to access the protected page. One simple way is to issue the command below in the terminal on the AttackBox.

`curl -H "x-middleware-subrequest: middleware" http://MACHINE_IP:3000/protected`

The command is like a usual `curl` command with one exception: It uses the `-H`, an equivalent of `--header`, to add an extra header to the HTTP GET request. Consequently, the above `curl` command allows the attacker to bypass all security controls and retrieve the protected page.

## Burp Or Caido

We can pass in the request to our proxy and add the `x-middleware-subrequest: middleware` header to it:

![](gitbook/cybersecurity/images/Pasted%20image%2020250325153823.png)

Now let's add the header:

![](gitbook/cybersecurity/images/Pasted%20image%2020250325153856.png)

We were able to bypass the `307` status code, flag is:

```
THM{NEXT_MDLE_JS}
```

## Detection

***

Recall from the previous tasks that CVE-2025-29927 for Next.js is a middleware authorisation bypass, resulting in the ability to access pages and routes previously requiring such authorisation.

This task will cover some techniques and rules that can be used to detect this attack taking place, both via logs and network traffic.

### Manual

Web server logs can potentially be used to discover evidence of this exploit taking place. However, it will depend on whether or not the web server is configured to record HTTP headers.  For instance, NodeJS allows for the logging of this specific HTTP header via `request.headers['x-middleware-subrequest'`

If the web application is proxied, the logging configuration on web servers such as Nginx or Apache2 will need to be modified to log this specific header. For example, **LogFormat** within Apache2 can be used:

`LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{x-middleware-subrequest}i\"" custom`

Once logging of this HTTP header is correctly setup, common tooling such as Grep, Yara, etc, can be used.

### Snort (v2)

The following Snort rule, when used as an IDS, can be used to detect CVE-2025-29927 taking place:

```bash
alert tcp any any -> any any (msg: "HTTP 'x-middleware-request' header detected, possible CVE-2025-29927 explotation"; content:"x-middleware-subrequest";  rawbytes; sid:10000001; rev:1)
```

This rule inspects the packet without factoring or considering any protocol, for example, the `http_headers` module. This is because the HTTP header "x-middleware-request" is not a [recognised header](https://docs.snort.org/rules/options/payload/http/header) within Snort at the time of writing.

First, we will add the Snort rule to our local rules. By default, on Ubuntu, this is located at `/etc/snort/rules/local.rules`. Now we will paste the code snippet above and save. Please note, you will need to change the `sid` value to another if you have existing rules.

Editing Snort's local.rules:

```bash
ubuntu@tryhackme-2404:~$ sudo nano /etc/snort/rules/local.rules
# $Id: local.rules,v 1.11 2004/07/23 20:14:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any -> any any (msg: "HTTP 'x-middleware-request' header detected"; content:"x-middleware-subrequest";  rawbytes; sid:10000001; rev:1)
```

Now, we can run Snort and test for detection. The following terminal below runs Snort in console mode for demonstration of the alert triggering.

Snort detectingCVE-2025-29927

```bash
ubuntu@tryhackme-2404:/var/log/snort$ sudo snort -q -l /var/log/snort -i ens5 -A console -c /etc/snort/snort.conf
03/24-20:16:13.424299  [**] [1:10000001:1] HTTP 'x-middleware-request' header detected [**] [Priority: 0] {TCP} 10.10.142.69:49432 -> 10.10.219.251:3000
```

### Zeek

Zeek offers a more comprehensive opportunity for threat detection within network traffic. For CVE-2025-29927, the following Zeek rule can be used:

```bash
module CVE_2025_29927;

export {
    redef enum Log::ID += { LOG };
    global log_policy: Log::PolicyHook = Log::IGNORE;

    event http_header(c: connection, is_orig: bool, name: string, value: string) {
        if (name == "x-middleware-subrequest" && value == "middleware")
            Log::write(HTTP::LOG, [
                $timestamp=c$start_time,
                $uid=c$uid,
                $id=c$id,
                $note="CVE_2025_29927_Exploit",
                $msg="Detected HTTP header associated with CVE-2025-29927",
                $header=name,
                $value=value
           ]);
        notice_info(c, "CVE-2025-29927 Exploit", fmt("The HTTP header '%s' associated with CVE-2025-29927 was detected", value));
    }
  }
}
```

Ensure that this file is saved with the `.zeek` extension in the configured directory for Zeek scripts. You will need to modify your `local.zeek` to include this script via adding `@load ./cve_2025_29927.zeek`.

Finally, restart Zeek to apply the configuration changes via `sudo zeekctl deploy`. If successful, Zeek will now alert when CVE-2025-29927 is detected:

```bash
[Connnection_ID] The HTTP header "x-middleware-subrequest" associated with CVE-2025-29927 was detected
```

## Conclusion

***

In this room, we covered why this vulnerability exists and how to exploit it. Checking the original posts about the discovery of this vulnerability provides an important reminder about the many vulnerabilities that still lurk in the source code of many popular applications. For patched versions, users are required to upgrade to the following:

* Next.js 15.x should upgrade to 15.2.3
* Next.js 14.x should upgrade to 14.2.25
* Next.js 13.x should upgrade to 13.5.9
* Next.js 12.x should upgrade to 12.3.5

If patching is infeasible, the only workaround is to block HTTP requests containing the `x-middleware-subrequest` from reaching your web application.
