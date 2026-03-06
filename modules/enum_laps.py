import os
import shlex

from module import BaseModule
from tool import Tool


class LAPSEnum(BaseModule):
    path = "enum/laps"
    description = "Enumerate legacy LAPS and Windows LAPS managed computers"
    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP or host address. If blank, the domain name will be used.",
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
        "include_legacy": {
            "default": "Yes",
            "description": "Enumerate legacy LAPS (ms-Mcs-AdmPwd*) attributes",
            "required": False,
            "boolean": True,
        },
        "include_windows_laps": {
            "default": "Yes",
            "description": "Enumerate Windows LAPS (msLAPS-*) attributes",
            "required": False,
            "boolean": True,
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

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(self.pane_b)
        if not tool.set_auth(from_module=True):
            return

        auth_params = tool.get_auth_params("bloodyad")
        if not auth_params:
            return

        base = [
            "bloodyAD",
            "--host",
            self.opts.dc_hostname,
            "--dc-ip",
            self.opts.dc_ip,
        ] + auth_params

        outputs = []
        managed_hosts = 0
        cleartext_values = 0
        had_bloodyad_error = False
        no_result_filters = set()

        if self.opts.include_legacy == "Yes":
            self.pane_a.write(
                "[cyan]Step 1:[/cyan] Enumerate legacy LAPS managed hosts"
            )
            command_parts = base + [
                "get",
                "search",
                "--base",
                "DOMAIN",
                "--filter",
                "(&(objectClass=computer)(ms-Mcs-AdmPwdExpirationTime=*))",
                "--attr",
                "sAMAccountName,dNSHostName,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime",
            ]
            lines = await self._run_and_capture(command_parts)
            outputs.extend(lines)
            query_error, query_no_results = self.inspect_bloodyad_output(lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying legacy LAPS objects; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in lines:
                lower = line.lower().strip()
                if lower.startswith("samaccountname:"):
                    managed_hosts += 1
                if lower.startswith("ms-mcs-admpwd:") and len(
                    line.split(":", 1)[-1].strip()
                ):
                    cleartext_values += 1

        if self.opts.include_windows_laps == "Yes":
            self.pane_a.write(
                "[cyan]Step 2:[/cyan] Enumerate Windows LAPS managed hosts"
            )
            command_parts = base + [
                "get",
                "search",
                "--base",
                "DOMAIN",
                "--filter",
                "(&(objectClass=computer)(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)))",
                "--attr",
                "sAMAccountName,dNSHostName,msLAPS-Password,msLAPS-EncryptedPassword,msLAPS-PasswordExpirationTime",
            ]
            lines = await self._run_and_capture(command_parts)
            outputs.extend(lines)
            query_error, query_no_results = self.inspect_bloodyad_output(lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying Windows LAPS objects; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in lines:
                lower = line.lower().strip()
                if lower.startswith("samaccountname:"):
                    managed_hosts += 1
                if lower.startswith("mslaps-password:") and len(
                    line.split(":", 1)[-1].strip()
                ):
                    cleartext_values += 1

        output = "\n".join(outputs)
        log_path = self.write_unique_log(output, f"laps_enum_{self.opts.domain}")
        if log_path:
            self.pane_a.write(f"✓ Saved LAPS enumeration output to `{log_path.name}`")

        self.pane_a.write(
            f"✓ Matched {managed_hosts} managed host line(s) across LAPS queries."
        )

        if cleartext_values:
            self.pane_a.write(
                f"[yellow][!] Matched {cleartext_values} readable cleartext LAPS value line(s).[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, validate local-admin reuse and privileged access with `enum/privileged` and host-by-host login testing."
            )
        if had_bloodyad_error:
            self.pane_a.write(
                "[yellow][!] Skipping clean LAPS exposure conclusion because bloodyAD reported runtime errors. Review raw output/log.[/yellow]"
            )
        elif no_result_filters and managed_hosts == 0:
            self.pane_a.write(
                f"[cyan]Info:[/cyan] No LAPS-managed hosts were returned for {len(no_result_filters)} LDAP query filter(s)."
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, confirm schema/attribute visibility and retry with an account that has broader directory read rights."
            )
        elif not cleartext_values:
            self.pane_a.write(
                "[green]✓ No cleartext LAPS password values were matched in parsed output.[/green]"
            )
            if managed_hosts:
                self.pane_a.write(
                    "[cyan]Tip:[/cyan] LAPS is deployed but values are protected; next, map read rights with `enum/acl` for LAPS attribute exposure."
                )
