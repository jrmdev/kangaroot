import os
import shlex

from pathlib import Path
from module import BaseModule

EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


class BloodHoundCollect(BaseModule):
    path = "bloodhound/collect"
    description = "Run BloodHound CE collector and generate a compatible ZIP"
    options = {
        "domain": {
            "default": "",
            "description": "Auth: Domain name (FQDN)",
            "required": True,
        },
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {
            "default": "",
            "description": "Auth: Password or NT Hash (for NTLM auth only)",
            "required": False,
        },
        "auth": {
            "default": "ntlm",
            "description": "Auth: Type (ntlm, krb)",
            "required": True,
        },
        "collection_method": {
            "default": "Default",
            "description": "Collection methods (comma-separated)",
            "required": False,
        },
        "nameserver": {
            "default": "",
            "description": "Alternative DNS server",
            "required": False,
        },
        "dns_tcp": {
            "default": "No",
            "description": "Use TCP for DNS",
            "required": False,
            "boolean": True,
        },
        "dns_timeout": {
            "default": "3",
            "description": "DNS query timeout in seconds",
            "required": False,
        },
        "domain_controller": {
            "default": "",
            "description": "Override Domain Controller host",
            "required": False,
        },
        "global_catalog": {
            "default": "",
            "description": "Override Global Catalog host",
            "required": False,
        },
        "workers": {
            "default": "10",
            "description": "Workers for computer enumeration",
            "required": False,
        },
        "exclude_dcs": {
            "default": "No",
            "description": "Skip DCs during computer enumeration",
            "required": False,
            "boolean": True,
        },
        "disable_pooling": {
            "default": "No",
            "description": "Disable subprocess pooling",
            "required": False,
            "boolean": True,
        },
        "disable_autogc": {
            "default": "No",
            "description": "Disable automatic GC selection",
            "required": False,
            "boolean": True,
        },
        "computerfile": {
            "default": "",
            "description": "Allowlist file of computer FQDNs",
            "required": False,
        },
        "cachefile": {
            "default": "",
            "description": "Cache file path",
            "required": False,
        },
        "ldap_channel_binding": {
            "default": "No",
            "description": "Enable LDAP channel binding",
            "required": False,
            "boolean": True,
        },
        "use_ldaps": {
            "default": "No",
            "description": "Use LDAPS (port 636)",
            "required": False,
            "boolean": True,
        },
        "output_prefix": {
            "default": "",
            "description": "Prefix prepended to output filenames",
            "required": False,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)

        command_parts = [
            "../tools/.bin/bloodhound-ce-python",
            "-d",
            self.opts.domain,
            "-c",
            self.opts.collection_method,
            "--zip",
        ]

        if self.opts.auth == "ntlm":
            command_parts.extend(["-u", self.opts.username, "--auth-method", "ntlm"])
            if self.is_nt_hash(self.opts.password):
                command_parts.extend(
                    ["--hashes", f"{EMPTY_LM_HASH}:{self.opts.password}"]
                )
            else:
                command_parts.extend(["-p", self.opts.password])
        else:
            ticket_path = Path(self.logs_dir) / f"{self.opts.username.lower()}.ccache"
            if not ticket_path.exists():
                self.pane_a.write(
                    f"[red][!] Kerberos ticket not found: {ticket_path.name}. Obtain one with kerberos/tgt first.[/red]"
                )
                return
            self.env["KRB5CCNAME"] = str(ticket_path)
            command_parts.extend(
                [
                    "-u",
                    self.opts.username,
                    "-k",
                    "-no-pass",
                    "--auth-method",
                    "kerberos",
                ]
            )

        if self.opts.nameserver:
            command_parts.extend(["-ns", self.opts.nameserver])
        if self.opts.dns_tcp == "Yes":
            command_parts.append("--dns-tcp")
        if self.opts.dns_timeout:
            command_parts.extend(["--dns-timeout", self.opts.dns_timeout])
        if self.opts.domain_controller:
            command_parts.extend(["-dc", self.opts.domain_controller])
        if self.opts.global_catalog:
            command_parts.extend(["-gc", self.opts.global_catalog])
        if self.opts.workers:
            command_parts.extend(["-w", self.opts.workers])
        if self.opts.exclude_dcs == "Yes":
            command_parts.append("--exclude-dcs")
        if self.opts.disable_pooling == "Yes":
            command_parts.append("--disable-pooling")
        if self.opts.disable_autogc == "Yes":
            command_parts.append("--disable-autogc")
        if self.opts.computerfile:
            command_parts.extend(["--computerfile", self.opts.computerfile])
        if self.opts.cachefile:
            command_parts.extend(["--cachefile", self.opts.cachefile])
        if self.opts.ldap_channel_binding == "Yes":
            command_parts.append("--ldap-channel-binding")
        if self.opts.use_ldaps == "Yes":
            command_parts.append("--use-ldaps")
        if self.opts.output_prefix:
            command_parts.extend(["-op", self.opts.output_prefix])

        existing_zips = set(Path(self.logs_dir).glob("*.zip"))

        async for line in self.run_command(shlex.join(command_parts), self.pane_c):
            self.pane_c.write(line)

        new_zips = [
            p for p in Path(self.logs_dir).glob("*.zip") if p not in existing_zips
        ]
        if new_zips:
            latest_zip = max(new_zips, key=lambda p: p.stat().st_mtime)
            self.pane_a.write(
                f"[green]✓ BloodHound collection ZIP created: {latest_zip.name}[/green]"
            )
        else:
            self.pane_a.write(
                "[yellow][!] BloodHound run completed but no new ZIP was detected in logs/.[/yellow]"
            )
