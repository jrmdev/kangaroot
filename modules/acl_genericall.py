import os

from module import BaseModule
from tool import Tool


class GenericAll(BaseModule):
    path = "acl/genericall"
    description = (
        "Add GenericAll from a chosen source user to a target account. "
        "Set cleanup=true to remove GenericAll instead."
    )
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
        "target_account": {
            "default": "",
            "description": "Target account to grant/revoke GenericAll on",
            "required": True,
        },
        "source_account": {
            "default": "",
            "description": "User principal to grant/revoke GenericAll for (defaults to auth username)",
            "required": False,
        },
        "cleanup": {
            "default": "false",
            "description": "Set true to remove GenericAll instead of adding it",
            "required": False,
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

        cleanup_raw = str(self.opts.cleanup or "false").strip().lower()
        truthy = {"1", "true", "yes", "y"}
        falsy = {"0", "false", "no", "n"}
        if cleanup_raw not in truthy | falsy:
            self.pane_a.write(
                "[red][!] Option `cleanup` must be one of: true/false/yes/no/1/0.[/red]"
            )
            return

        cleanup = cleanup_raw in truthy
        source_account = str(self.opts.source_account or "").strip() or self.opts.username
        if not source_account:
            self.pane_a.write(
                "[red][!] Option `source_account` is empty and auth `username` is missing.[/red]"
            )
            return

        if cleanup:
            tool.title(f"Remove GenericAll for {source_account} on target account")
            await tool.remove_genericall(self.opts.target_account, source_account)
            return

        tool.title(f"Add GenericAll for {source_account} on target account")
        await tool.add_genericall(self.opts.target_account, source_account)
