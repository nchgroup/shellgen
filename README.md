# shellgen
**shellgen** is a custom script that prints in prompt a lot of different reverse shells options with a given IP and PORT to copy and paste

# Supported
* Linux
    * reverse
    * bind
* Windows
    * reverse
* PHP Web Shell

# Usage

### Help

```
$ python3 shellgen.py -h                
usage: shellgen.py [-h] {linux_rev,windows_rev,linux_bind,php_shell} ...

ShellGen - Shells Generator

options:
  -h, --help            show this help message and exit

subcommands:
  {linux_rev,windows_rev,linux_bind,php_shell}
    linux_rev           Linux reverse shells
    windows_rev         Windows reverse shells
    linux_bind          Linux bind shells
    php_shell           PHP shells
```

### Linux Reverse Shell

```
$ python3 shellgen.py linux_rev --help
usage: shellgen.py linux_rev [-h] [--shell SHELLTYPE] --ip IPDST [--port PORTDST] [--raw]

options:
  -h, --help            show this help message and exit
  --shell SHELLTYPE, -s SHELLTYPE
                        Type of shell
  --ip IPDST, -ip IPDST
                        IP destination
  --port PORTDST, -p PORTDST
                        Port destination
  --raw, -r             Raw shell
```

### Windows Reverse Shell

```
$ python3 shellgen.py windows_rev --help                      
usage: shellgen.py windows_rev [-h] --ip IPDST [--port PORTDST] [--raw]

options:
  -h, --help            show this help message and exit
  --ip IPDST, -ip IPDST
                        IP destination
  --port PORTDST, -p PORTDST
                        Port destination
  --raw, -r             Raw shell
```

### Linux Bind Shell

```
$ python3 shellgen.py linux_bind --help
usage: shellgen.py linux_bind [-h] [--shell SHELLTYPE] [--port PORTSRC] [--raw]

options:
  -h, --help            show this help message and exit
  --shell SHELLTYPE, -s SHELLTYPE
                        Type of shell
  --port PORTSRC, -p PORTSRC
                        Port source
  --raw, -r             Raw shell
```

### PHP Web Shell

```
$ python3 shellgen.py php_shell --help
usage: shellgen.py php_shell [-h] [-m {request,get,post,REQUEST,GET,POST}] [-p PARAMETER] [--raw]

options:
  -h, --help            show this help message and exit
  -m {request,get,post,REQUEST,GET,POST}, --method {request,get,post,REQUEST,GET,POST}
                        Type of method
  -p PARAMETER, --parameter PARAMETER
                        Parameter ex: ?<parameter>=whoami
  --raw, -r             Raw shell
```

# Colaborators

* https://github.com/elborikua
