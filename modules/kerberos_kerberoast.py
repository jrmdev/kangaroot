import os

from module import BaseModule
from tool import Tool

class Kerberoast(BaseModule):
    path = "kerberos/kerberoast"
    description = "Kerberoasting attack."
    options = {
        "dc_ip": {"default": "", "description": "DC IP. If blank, domain FQDN will be used.", "required": False},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash", "required": True},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
        "target_account": {"default": "", "description": "Target account to Kerberoast (empty = ALL)", "required": False},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, opts, pane):

        tool = Tool(self)

        os.chdir(self.logs_dir)

        if not tool.set_auth(from_module=True):
            return
        await tool.kerberoast(self.opts.target_account)

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)
        await self._run(self.opts, pane=self.pane_c)
