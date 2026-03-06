import os

from tool import Tool
from module import BaseModule


class DelegationEnum(BaseModule):
    path = "enum/delegation"
    description = (
        "Enumerate delgations that could be abused (Constrained, Unconstrained, RBCD)"
    )
    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP or host address. If blank, the domain name will be used.",
            "required": False,
        },
        "target_domain": {
            "default": "",
            "description": "Target domain (FQDN) (If empty, auth domain will be used.)",
            "required": False,
        },
        "domain": {
            "default": "",
            "description": "Auth: Domain name (FQDN)",
            "required": True,
        },
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {
            "default": "",
            "description": "Auth: Password or NT Hash (for NTLM auth only)",
            "required": False,
        },
        "auth": {
            "default": "ntlm",
            "description": "Auth: Type (ntlm, krb)",
            "required": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def run(self):
        if not self.validate_options():
            return

        tool = Tool(self)

        os.chdir(self.logs_dir)
        self.opts.dc_ip = self.adutils.get_dc_ip(self.opts.dc_ip, self.opts.domain)
        self.opts.dc_hostname = self.adutils.get_dc_hostname(
            self.opts.dc_ip, self.opts.domain
        )

        if not tool.set_auth(from_module=True):
            return
        res = await tool.find_delegations(self.opts.target_domain)

        if not res:
            return

        lines = [line.strip() for line in res.splitlines()]
        unconstrained_hits = 0
        constrained_hits = 0
        rbcd_hits = 0
        for line in lines:
            lower = line.lower()
            if "unconstrained" in lower:
                unconstrained_hits += 1
            if "constrained" in lower and "unconstrained" not in lower:
                constrained_hits += 1
            if "resource-based constrained" in lower or "rbcd" in lower:
                rbcd_hits += 1

        if unconstrained_hits:
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Unconstrained delegation found. Next, try `delegation/unconstrained` to hunt coercible targets and capture TGTs."
            )
        if constrained_hits:
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Constrained delegation found. Next, try `delegation/constrained` or `delegation/constrained_with_pt` to validate S4U abuse paths."
            )
        if rbcd_hits:
            self.pane_a.write(
                "[cyan]Tip:[/cyan] RBCD-style entries found. Next, try `delegation/rbcd` using a controlled machine account."
            )
        if not any((unconstrained_hits, constrained_hits, rbcd_hits)):
            self.pane_a.write(
                "[cyan]Tip:[/cyan] No obvious delegation abuse indicators were parsed. Next, try `enum/trust` and `enum/acl` for cross-domain or ACL-based pivots."
            )

        self.write_unique_log(res, f"findDelegation_{self.opts.domain}")
