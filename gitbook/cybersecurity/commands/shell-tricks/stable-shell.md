---
sticker: emoji//1f41a
---

# STABLE SHELL

* SPAWNING A STABLE SHELL:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```
