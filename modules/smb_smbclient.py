import os

from module import BaseModule
from tool import Tool

class SMBClient(BaseModule):
    path = "smb/client"
    description = "SMB Client module"
    options = {
        "target": {"default": "", "description": "Computer to connect to", "required": True},
        "share": {"default": "C$", "description": "Share to connect to", "required": True},
        "cmd": {"default": "ls", "description": "Command to execute within the share", "required": True},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash", "required": True},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, opts, pane):

        tool = Tool(self)

        os.chdir(self.logs_dir)

        if not tool.set_auth(from_module=True):
            return
        await tool.smbclient(self.opts.target, share=self.opts.share, cmd=self.opts.cmd)

    async def run(self):
        if not self.validate_options():
            return

        await self._run(self.opts, self.pane_c)
