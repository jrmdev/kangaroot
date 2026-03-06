import os

from module import BaseModule
from tool import Tool


class SetPassword(BaseModule):
    path = "acl/setpasswd"
    description = "Set a target account's password. Requires GenericAll / GenericWrite."
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
            "description": "Target account whose password will be changed",
            "required": True,
        },
        "target_password": {
            "default": "",
            "description": "New password to set for the account",
            "required": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run(self, opts, pane):

        # os.chdir(self.logs_dir)
        # opts.dc_ip = self.adutils.get_dc_ip(opts.dc_ip, opts.domain)
        # opts.dc_hostname = self.adutils.get_dc_hostname(opts.dc_ip, opts.domain)

        # bloodyad = BloodyADWrapper()
        # bloodyad.set_opts(self)

        # auth_param = self.auth_param_bloodyad(opts.auth, opts.domain, opts.username, opts.password)
        # if not await bloodyad.run('set', 'password', auth_param, opts.target_account, opts.target_password, None, "Step 1: Set password for the target account."):
        #     return

        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(pane)
        tool.title("Set password for the target account")
        if not tool.set_auth(from_module=True):
            return

        await tool.set_passwd(opts.target_account, opts.target_password)

    async def run(self):
        if not self.validate_options():
            return

        await self._run(self.opts, self.pane_b)
