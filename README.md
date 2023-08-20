# shellgen
**shellgen** is a custom script that prints in prompt a lot of different reverse shells options with a given IP and PORT to copy and paste

# Supported
* Linux
    * reverse
    * bind
* Windows
    * reverse
    * download execute
* PHP Web Shell

# Usage

### Help

```
$ python3 shellgen.py --help
usage: shellgen.py [-h] {linux_rev,linux_bind,windows_rev,download_exec,php_shell} ...

ShellGen - Shells Generator

options:
  -h, --help            show this help message and exit

subcommands:
  {linux_rev,linux_bind,windows_rev,download_exec,php_shell}
    linux_rev           Linux reverse shells
    linux_bind          Linux bind shells
    windows_rev         Windows reverse shells
    download_exec       Windows shellcode generator for download and execute
    php_shell           PHP shells
```

### Linux Reverse Shell

```
$ python3 shellgen.py linux_rev --help
usage: shellgen.py linux_rev [-h] [--shell SHELLTYPE] --ip IPDST [--port PORTDST] [--raw] [--encode {b64,b64_utf16,url,durl,hex,json}]

options:
  -h, --help            show this help message and exit
  --shell SHELLTYPE, -s SHELLTYPE
                        Type of shell
  --ip IPDST, -ip IPDST
                        IP destination
  --port PORTDST, -p PORTDST
                        Port destination
  --raw, -r             Raw payload
  --encode {b64,b64_utf16,url,durl,hex,json}, -e {b64,b64_utf16,url,durl,hex,json}
                        Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json:
                        json_escape
```

### Linux Bind Shell

```
$ python3 shellgen.py linux_bind --help 
usage: shellgen.py linux_bind [-h] [--shell SHELLTYPE] [--port PORTSRC] [--raw] [--encode {b64,b64_utf16,url,durl,hex,json}]

options:
  -h, --help            show this help message and exit
  --shell SHELLTYPE, -s SHELLTYPE
                        Type of shell
  --port PORTSRC, -p PORTSRC
                        Port source
  --raw, -r             Raw payload
  --encode {b64,b64_utf16,url,durl,hex,json}, -e {b64,b64_utf16,url,durl,hex,json}
                        Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json:
                        json_escape
```

### Windows Reverse Shell

```
$ python3 shellgen.py windows_rev --help
usage: shellgen.py windows_rev [-h] --ip IPDST [--port PORTDST] [--raw] [--encode {b64,b64_utf16,url,durl,hex,json}]

options:
  -h, --help            show this help message and exit
  --ip IPDST, -ip IPDST
                        IP destination
  --port PORTDST, -p PORTDST
                        Port destination
  --raw, -r             Raw payload
  --encode {b64,b64_utf16,url,durl,hex,json}, -e {b64,b64_utf16,url,durl,hex,json}
                        Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json:
                        json_escape
```

### Windows Download and Execute

```
$ python3 shellgen.py download_exec -h
usage: shellgen.py download_exec [-h] --url URL [-f {msf,hex,b64}] [--raw]

options:
  -h, --help            show this help message and exit
  --url URL, -u URL     Url dropper
  -f {msf,hex,b64}, --format {msf,hex,b64}
                        Type of format => msf: metasploit, hex: hexadecimal, b64: base64
  --raw, -r             Raw payload
```


### PHP Web Shell

```
$ python3 shellgen.py php_shell -h  
usage: shellgen.py php_shell [-h] [-m {request,get,post,REQUEST,GET,POST}] [-p PARAMETER] [--raw] [--encode {b64,b64_utf16,url,durl,hex,json}]

options:
  -h, --help            show this help message and exit
  -m {request,get,post,REQUEST,GET,POST}, --method {request,get,post,REQUEST,GET,POST}
                        Type of method
  -p PARAMETER, --parameter PARAMETER
                        Parameter ex: ?<parameter>=whoami
  --raw, -r             Raw payload
  --encode {b64,b64_utf16,url,durl,hex,json}, -e {b64,b64_utf16,url,durl,hex,json}
                        Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json:
                        json_escape
```

# Colaborators

* https://github.com/elborikua
