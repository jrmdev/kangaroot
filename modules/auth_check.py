import os
import shlex

from pathlib import Path

from module import BaseModule
from tool import Tool


class AuthCheck(BaseModule):
    path = "auth/check"
    description = "Validate domain credentials and check local admin access on a target"
    options = {
        "target": {
            "default": "",
            "description": "Target host to test local admin access against",
            "required": True,
        },
        "share": {
            "default": "C$",
            "description": "Administrative share used for admin check",
            "required": False,
        },
        "dc_ip": {
            "default": "",
            "description": "Domain controller IP/host. If blank, one is auto-resolved.",
            "required": False,
        },
        "domain": {
            "default": "",
            "description": "Auth: Domain name (FQDN)",
            "required": True,
        },
        "username": {
            "default": "",
            "description": "Auth: Username",
            "required": True,
        },
        "password": {
            "default": "",
            "description": "Auth: Password or NT hash (required for NTLM)",
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

    async def _run_and_capture(self, command_parts: list[str]) -> list[str]:
        captured = []
        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            self.pane_b.write(line)
            captured.append(line)
        return captured

    def _classify_domain_check(
        self, lines: list[str], fatal_error: bool, no_result_filters: list[str]
    ) -> str:
        lower_lines = [line.lower() for line in lines]
        lower_blob = "\n".join(lower_lines)

        invalid_cred_markers = [
            "invalidcredentials",
            "status_logon_failure",
            "kdc_err_preauth_failed",
            "kdc_err_client_revoked",
            "kdc_err_c_principal_unknown",
            "the attempted logon is invalid",
        ]
        if any(marker in lower_blob for marker in invalid_cred_markers):
            return "invalid_credentials"

        connectivity_markers = [
            "timed out",
            "connection refused",
            "name or service not known",
            "temporary failure in name resolution",
            "no route to host",
        ]
        if any(marker in lower_blob for marker in connectivity_markers):
            return "connectivity_error"

        if fatal_error:
            return "runtime_error"

        if any("samaccountname:" in line for line in lower_lines):
            return "ok"

        if no_result_filters:
            return "no_result"

        return "unknown"

    def _classify_admin_check(self, lines: list[str]) -> str:
        lower_blob = "\n".join(line.lower() for line in lines)

        invalid_cred_markers = [
            "status_logon_failure",
            "invalidcredentials",
            "kdc_err_preauth_failed",
            "kdc_err_client_revoked",
            "the attempted logon is invalid",
        ]
        if any(marker in lower_blob for marker in invalid_cred_markers):
            return "invalid_credentials"

        unreachable_markers = [
            "connection refused",
            "name or service not known",
            "temporary failure in name resolution",
            "timed out",
            "no route to host",
            "connection reset by peer",
        ]
        if any(marker in lower_blob for marker in unreachable_markers):
            return "target_unreachable"

        not_admin_markers = [
            "status_access_denied",
            "access denied",
            "treeconnect failed",
            "nt_status_access_denied",
        ]
        if any(marker in lower_blob for marker in not_admin_markers):
            return "not_admin"

        if "type help for list of commands" in lower_blob:
            return "admin"

        if "traceback (most recent call last):" in lower_blob:
            return "runtime_error"

        return "unknown"

    async def _check_domain_auth(self, tool: Tool):
        self.pane_a.write("[cyan]Step 1:[/cyan] Validate credentials against the domain")

        auth_params = tool.get_auth_params("bloodyad")
        if not auth_params:
            return False, "auth_setup_failed", []

        query_user = self.opts.username.split("@", 1)[0]
        command_parts = [
            "../tools/.bin/bloodyAD",
            "--host",
            self.opts.dc_hostname,
            "--dc-ip",
            self.opts.dc_ip,
        ] + auth_params + [
            "get",
            "search",
            "--base",
            "DOMAIN",
            "--filter",
            f"(sAMAccountName={query_user})",
            "--attr",
            "sAMAccountName,distinguishedName",
        ]

        lines = await self._run_and_capture(command_parts)
        fatal_error, no_result_filters = self.inspect_bloodyad_output(lines)
        status = self._classify_domain_check(lines, fatal_error, no_result_filters)

        return status == "ok", status, lines

    async def _check_target_admin(self, tool: Tool):
        self.pane_a.write(
            f"[cyan]Step 2:[/cyan] Check admin access on `{self.opts.target}` via `{self.opts.share}`"
        )

        auth_params = tool.get_auth_params("impacket", target=self.opts.target)
        if not auth_params:
            return False, "auth_setup_failed", []

        cmd_file = Path(self.logs_dir) / "auth_check_smbclient.cmd"
        cmd_file.write_text(f"use {self.opts.share}\nls\nexit\n", encoding="utf-8")

        try:
            command_parts = ["smbclient.py", "-inputfile", str(cmd_file)] + auth_params
            lines = await self._run_and_capture(command_parts)
        finally:
            cmd_file.unlink(missing_ok=True)

        status = self._classify_admin_check(lines)
        return status == "admin", status, lines

    def _write_summary(self, domain_status: str, admin_status: str):
        domain_messages = {
            "ok": "[green]PASS[/green] Domain credential validation succeeded.",
            "invalid_credentials": "[red]FAIL[/red] Domain credential validation failed (invalid credentials).",
            "connectivity_error": "[yellow]WARN[/yellow] Domain validation could not complete due to connectivity/DNS issues.",
            "runtime_error": "[red]FAIL[/red] Domain validation failed due to tool/runtime errors.",
            "no_result": "[yellow]WARN[/yellow] Domain bind likely worked, but no matching user object was returned.",
            "auth_setup_failed": "[red]FAIL[/red] Domain validation could not start due to auth setup failure.",
            "unknown": "[yellow]WARN[/yellow] Domain validation produced an inconclusive result.",
        }
        admin_messages = {
            "admin": f"[green]YES[/green] `{self.opts.username}` appears to have admin share access on `{self.opts.target}`.",
            "not_admin": f"[yellow]NO[/yellow] `{self.opts.username}` does not appear to have admin share access on `{self.opts.target}`.",
            "invalid_credentials": f"[red]FAIL[/red] Target admin check failed due to invalid credentials on `{self.opts.target}`.",
            "target_unreachable": f"[yellow]WARN[/yellow] Target admin check could not complete because `{self.opts.target}` was unreachable.",
            "runtime_error": "[red]FAIL[/red] Target admin check failed due to tool/runtime errors.",
            "auth_setup_failed": "[red]FAIL[/red] Target admin check could not start due to auth setup failure.",
            "unknown": "[yellow]WARN[/yellow] Target admin check produced an inconclusive result.",
        }

        self.pane_a.write(
            f"[bold]Domain credentials:[/bold] {domain_messages.get(domain_status, domain_messages['unknown'])}"
        )
        self.pane_a.write(
            f"[bold]Admin on target:[/bold] {admin_messages.get(admin_status, admin_messages['unknown'])}"
        )

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(self.pane_b)
        if not tool.set_auth(from_module=True):
            return

        _, domain_status, domain_lines = await self._check_domain_auth(tool)
        _, admin_status, admin_lines = await self._check_target_admin(tool)

        output = "\n".join(
            [
                "=== Domain Credential Check (bloodyAD) ===",
                *domain_lines,
                "",
                "=== Target Admin Check (smbclient) ===",
                *admin_lines,
            ]
        )
        log_path = self.write_unique_log(output, f"auth_check_{self.opts.target}")
        if log_path:
            self.pane_a.write(f"✓ Saved auth check output to `{log_path.name}`")

        self._write_summary(domain_status, admin_status)
