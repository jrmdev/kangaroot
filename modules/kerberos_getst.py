import os
from pathlib import Path

from module import BaseModule
from tool import Tool


class GetST(BaseModule):
    path = "kerberos/st"
    description = "Request a Kerberos service ticket"
    info = """Requests a service ticket (TGS) and saves it as a ccache file.

Required settings:
  - spn
  - domain
  - username
  - auth (ntlm or krb)
  - password (required when auth=ntlm)

Optional settings:
  - dc_ip
  - impersonate
  - altservice
  - additional_ticket
  - u2u
  - self_only
  - force_forwardable
  - renew
  - ts
  - debug"""
    options = {
        "spn": {"default": "", "description": "SPN (service/server) to request a service ticket for", "required": True},
        "dc_ip": {"default": "", "description": "DC IP. If blank, domain FQDN will be used.", "required": False},
        "impersonate": {"default": "", "description": "Target username to impersonate via S4U2Self", "required": False},
        "altservice": {"default": "", "description": "Alternate service name/SPN for the ticket", "required": False},
        "additional_ticket": {"default": "", "description": "Path to forwardable ticket (.ccache) for S4U2Proxy", "required": False},
        "u2u": {"default": "No", "description": "Request a User-to-User ticket", "required": False, "boolean": True},
        "self_only": {"default": "No", "description": "Only perform S4U2Self (no S4U2Proxy)", "required": False, "boolean": True},
        "force_forwardable": {"default": "No", "description": "Force service ticket from S4U2Self to be forwardable", "required": False, "boolean": True},
        "renew": {"default": "No", "description": "Set RENEW option on the TGT used for authentication", "required": False, "boolean": True},
        "ts": {"default": "No", "description": "Add timestamp to every logging output", "required": False, "boolean": True},
        "debug": {"default": "No", "description": "Turn DEBUG output on", "required": False, "boolean": True},
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

        params = ["-spn", self.opts.spn]

        if self.opts.altservice:
            params.extend(["-altservice", self.opts.altservice])
        if self.opts.impersonate:
            params.extend(["-impersonate", self.opts.impersonate])
        if self.opts.additional_ticket:
            params.extend(["-additional-ticket", self.opts.additional_ticket])
        if self.opts.u2u == "Yes":
            params.append("-u2u")
        if self.opts.self_only == "Yes":
            params.append("-self")
        if self.opts.force_forwardable == "Yes":
            params.append("-force-forwardable")
        if self.opts.renew == "Yes":
            params.append("-renew")
        if self.opts.ts == "Yes":
            params.append("-ts")
        if self.opts.debug == "Yes":
            params.append("-debug")

        ticket = await tool.get_st(params)
        if ticket and Path(ticket).exists():
            self.pane_a.write(f"[green]Obtained service ticket and saved ccache to {ticket}[/green]")
