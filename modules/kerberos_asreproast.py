import os

from module import BaseModule
from tool import Tool

class ASRepRoast(BaseModule):
    path = "kerberos/asreproast"
    description = "AS-REP Roasting attack."
    options = {
        "dc_ip": {"default": "", "description": "DC IP. If blank, domain FQDN will be used.", "required": False},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash", "required": True},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, opts, pane):

        os.chdir(self.logs_dir)
        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return

        await tool.asreproast()

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)
        await self._run(self.opts, pane=self.pane_c)
