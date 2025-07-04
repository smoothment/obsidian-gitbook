---
sticker: lucide//database
---

# Subverting Query Logic

***

Now that we have a basic idea about how SQL statements work let us get started with SQL injection. Before we start executing entire SQL queries, we will first learn to modify the original query by injecting the `OR` operator and using SQL comments to subvert the original query's logic. A basic example of this is bypassing web authentication, which we will demonstrate in this section.

***

### Authentication Bypass

Consider the following administrator login page.

![admin\_panel](https://academy.hackthebox.com/storage/modules/33/admin_panel.png)

We can log in with the administrator credentials `admin / p@ssw0rd`.

![admin\_creds](https://academy.hackthebox.com/storage/modules/33/admin_creds.png)

The page also displays the SQL query being executed to understand better how we will subvert the query logic. Our goal is to log in as the admin user without using the existing password. As we can see, the current SQL query being executed is:

```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

The page takes in the credentials, then uses the `AND` operator to select records matching the given username and password. If the `MySQL` database returns matched records, the credentials are valid, so the `PHP` code would evaluate the login attempt condition as `true`. If the condition evaluates to `true`, the admin record is returned, and our login is validated. Let us see what happens when we enter incorrect credentials.

![admin\_incorrect](https://academy.hackthebox.com/storage/modules/33/admin_incorrect.png)

As expected, the login failed due to the wrong password leading to a `false` result from the `AND` operation.

***

### SQLi Discovery

Before we start subverting the web application's logic and attempting to bypass the authentication, we first have to test whether the login form is vulnerable to SQL injection. To do that, we will try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:

| Payload | URL Encoded |
| ------- | ----------- |
| `'`     | `%27`       |
| `"`     | `%22`       |
| `#`     | `%23`       |
| `;`     | `%3B`       |
| `)`     | `%29`       |

Note: In some cases, we may have to use the URL encoded version of the payload. An example of this is when we put our payload directly in the URL 'i.e. HTTP GET request'.

So, let us start by injecting a single quote:

![quote\_error](https://academy.hackthebox.com/storage/modules/33/quote_error.png)

We see that a SQL error was thrown instead of the `Login Failed` message. The page threw an error because the resulting query was:

```sql
SELECT * FROM logins WHERE username=''' AND password = 'something';
```

As discussed in the previous section, the quote we entered resulted in an odd number of quotes, causing a syntax error. One option would be to comment out the rest of the query and write the remainder of the query as part of our injection to form a working query. Another option is to use an even number of quotes within our injected query, such that the final query would still work.

***

### OR Injection

We would need the query always to return `true`, regardless of the username and password entered, to bypass the authentication. To do this, we can abuse the `OR` operator in our SQL injection.

As previously discussed, the MySQL documentation for [operation precedence](https://dev.mysql.com/doc/refman/8.0/en/operator-precedence.html) states that the `AND` operator would be evaluated before the `OR` operator. This means that if there is at least one `TRUE` condition in the entire query along with an `OR` operator, the entire query will evaluate to `TRUE` since the `OR` operator returns `TRUE` if one of its operands is `TRUE`.

An example of a condition that will always return `true` is `'1'='1'`. However, to keep the SQL query working and keep an even number of quotes, instead of using ('1'='1'), we will remove the last quote and use ('1'='1), so the remaining single quote from the original query would be in its place.

So, if we inject the below condition and have an `OR` operator between it and the original condition, it should always return `true`:

```sql
admin' or '1'='1
```

The final query should be as follow:

```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

This means the following:

```ad-important
- If username is `admin`  
    `OR`
- If `1=1` return `true` 'which always returns `true`'  
    `AND`
- If password is `something`
```

![or\_inject\_diagram](https://academy.hackthebox.com/storage/modules/33/or_inject_diagram.png)

The `AND` operator will be evaluated first, and it will return `false`. Then, the `OR` operator would be evaluated, and if either of the statements is `true`, it would return `true`. Since `1=1` always returns `true`, this query will return `true`, and it will grant us access.

Note: The payload we used above is one of many auth bypass payloads we can use to subvert the authentication logic. You can find a comprehensive list of SQLi auth bypass payloads in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass), each of which works on a certain type of SQL queries.

***

### Auth Bypass with OR operator

Let us try this as the username and see the response. ![inject\_success](https://academy.hackthebox.com/storage/modules/33/inject_success.png)

We were able to log in successfully as admin. However, what if we did not know a valid username? Let us try the same request with a different username this time.

![notadmin\_fail](https://academy.hackthebox.com/storage/modules/33/notadmin_fail.png)

The login failed because `notAdmin` does not exist in the table and resulted in a false query overall.

![notadmin\_diagram](https://academy.hackthebox.com/storage/modules/33/notadmin_diagram_1.png)

To successfully log in once again, we will need an overall `true` query. This can be achieved by injecting an `OR` condition into the password field, so it will always return `true`. Let us try `something' or '1'='1` as the password.

![password\_or\_injection](https://academy.hackthebox.com/storage/modules/33/password_or_injection.png)

The additional `OR` condition resulted in a `true` query overall, as the `WHERE` clause returns everything in the table, and the user present in the first row is logged in. In this case, as both conditions will return `true`, we do not have to provide a test username and password and can directly start with the `'` injection and log in with just `' or '1' = '1`.

![basic\_auth\_bypass](https://academy.hackthebox.com/storage/modules/33/basic_auth_bypass.png)

This works since the query evaluate to `true` irrespective of the username or password.

## Question

***

![](gitbook/cybersecurity/images/Pasted%20image%2020250131143341.png)

Let's go into the site:

![](gitbook/cybersecurity/images/Pasted%20image%2020250131143354.png)

At first sight, we encounter a login page, we can pass the following query to check if it's vulnerable to SQLI:

![](gitbook/cybersecurity/images/Pasted%20image%2020250131143614.png)

We can breakdown the command in the following way:

```ad-summary
### ⚙️ **Original SQL Query (Expected by the Login System):**



`SELECT * FROM users 
WHERE username = '[input_username]' 
  AND password = '[input_password]';`

---

### 💥 **The Attacker's Input:**

- **Username:** `admin' or 1=1 --`
    
- **Password:** `****` (irrelevant, as it will be commented out)
    

---

### 🔄 **Modified Query After Injection:**

`SELECT * FROM users 
WHERE username = 'admin' OR 1=1 -- ' AND password = '****';`

- The `'` in `admin'` closes the username string prematurely.
    
- `OR 1=1` adds a condition that is **always true**.
    
- `--` comments out the rest of the query (including the password check).
    

---

### 🔑 **Why This Works:**

1. **Bypassing Authentication**:
    
    - The `OR 1=1` makes the entire `WHERE` clause true for **all rows** in the `users` table.
        
    - The query returns **all users**, and the application often logs in as the first user (usually `admin`).
        
2. **Ignoring the Password**:
    
    - The `--` (SQL comment) removes the password check entirely. Even a wrong password will work.
        

---

### 🛡️ **Impact:**

- The attacker gains unauthorized access as `admin` (or another privileged user).
    
- This works if the application:
    
    - Does **not sanitize user inputs**.
        
    - Uses **concatenation** to build SQL queries (instead of parameterized queries).
```

Nice, now that we know that works, we can simply use:

`tom' or '1'='1 -- -`

Or we can shorten the command by simply using:

`tom' or '1'='1`

Like this, we'd be able to bypass the login page:

![](gitbook/cybersecurity/images/Pasted%20image%2020250131144251.png)

Flag is: `202a1d1a8b195d5e9a57e434cc16000c`
