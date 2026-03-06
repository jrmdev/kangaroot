import os

from module import BaseModule
from tool import Tool

class GetTGT(BaseModule):
    path = "kerberos/tgt"
    description = "Get a TGT for user authentication"
    options = {
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash", "required": True},
        "dc_ip": {"default": "", "description": "DC IP. If blank, domain FQDN will be used.", "required": False},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, domain: str, username: str, password: str):
        os.chdir(self.logs_dir)
        tool = Tool(self)
        if not tool.set_auth(auth="ntlm", domain=domain, username=username, password=password):
            return

        ticket = await tool.get_tgt()

        if ticket and os.path.exists(ticket):
            self.pane_a.write(f"[green]✓ Obtained TGT for {username}@{domain}[/green]")

    async def run(self):
        if not self.validate_options():
            return

        await self._run(self.opts.domain, self.opts.username, self.opts.password)
