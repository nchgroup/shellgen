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
$ python3 shellgen.py
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


Subcomando 'linux_rev':
usage: shellgen.py linux_rev [-h] [-s SHELLTYPE] -ip IPDST [-p PORTDST] [-r] [-e {b64,b64_utf16,url,durl,hex,json}]

options:
  -h, --help            show this help message and exit
  -s SHELLTYPE, --shell SHELLTYPE
                        Type of shell
  -ip IPDST, --ip IPDST
                        IP destination
  -p PORTDST, --port PORTDST
                        Port destination
  -r, --raw             Raw payload
  -e {b64,b64_utf16,url,durl,hex,json}, --encode {b64,b64_utf16,url,durl,hex,json}
                        Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json:
                        json_escape


Subcomando 'linux_bind':
usage: shellgen.py linux_bind [-h] [-s SHELLTYPE] [-p PORTSRC] [-r] [-e {b64,b64_utf16,url,durl,hex,json}]

options:
  -h, --help            show this help message and exit
  -s SHELLTYPE, --shell SHELLTYPE
                        Type of shell
  -p PORTSRC, --port PORTSRC
                        Port source
  -r, --raw             Raw payload
  -e {b64,b64_utf16,url,durl,hex,json}, --encode {b64,b64_utf16,url,durl,hex,json}
                        Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json:
                        json_escape


Subcomando 'windows_rev':
usage: shellgen.py windows_rev [-h] -ip IPDST [-p PORTDST] [-r] [-e {b64,b64_utf16,url,durl,hex,json}]

options:
  -h, --help            show this help message and exit
  -ip IPDST, --ip IPDST
                        IP destination
  -p PORTDST, --port PORTDST
                        Port destination
  -r, --raw             Raw payload
  -e {b64,b64_utf16,url,durl,hex,json}, --encode {b64,b64_utf16,url,durl,hex,json}
                        Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json:
                        json_escape


Subcomando 'download_exec':
usage: shellgen.py download_exec [-h] -u URL [-f {msf,hex,b64}] [-r]

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Url dropper
  -f {msf,hex,b64}, --format {msf,hex,b64}
                        Type of format => msf: metasploit, hex: hexadecimal, b64: base64
  -r, --raw             Raw payload


Subcomando 'php_shell':
usage: shellgen.py php_shell [-h] [-m {request,get,post,REQUEST,GET,POST}] [-p PARAMETER] [-r] [-e {b64,b64_utf16,url,durl,hex,json}]

options:
  -h, --help            show this help message and exit
  -m {request,get,post,REQUEST,GET,POST}, --method {request,get,post,REQUEST,GET,POST}
                        Type of method
  -p PARAMETER, --parameter PARAMETER
                        Parameter ex: ?<parameter>=whoami
  -r, --raw             Raw payload
  -e {b64,b64_utf16,url,durl,hex,json}, --encode {b64,b64_utf16,url,durl,hex,json}
                        Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json:
                        json_escape
```

# Colaborators

* https://github.com/elborikua
