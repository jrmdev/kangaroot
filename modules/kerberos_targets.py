import os
import re
import shlex

from module import BaseModule
from tool import Tool


class KerberosTargets(BaseModule):
    path = "kerberos/targets"
    description = (
        "Enumerate Kerberos-relevant target accounts (SPN, AS-REP, delegation flags)"
    )
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
        "include_spn_accounts": {
            "default": "Yes",
            "description": "Enumerate SPN-bearing accounts (kerberoast candidates)",
            "required": False,
            "boolean": True,
        },
        "include_asrep_accounts": {
            "default": "Yes",
            "description": "Enumerate users with DONT_REQ_PREAUTH set",
            "required": False,
            "boolean": True,
        },
        "include_delegation_flags": {
            "default": "Yes",
            "description": "Enumerate user accounts with delegation-related flags",
            "required": False,
            "boolean": True,
        },
        "include_computers": {
            "default": "No",
            "description": "Include computer accounts in SPN query",
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

    def _extract_int(self, line: str):
        match = re.search(r"(-?\d+)", line)
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

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
        spn_targets = 0
        asrep_targets = 0
        delegation_targets = 0
        privileged_hits = 0
        rc4_only_hits = 0
        had_bloodyad_error = False
        no_result_filters = set()

        if self.opts.include_spn_accounts == "Yes":
            self.pane_a.write("[cyan]Step 1:[/cyan] Enumerate SPN-bearing accounts")
            spn_filter = "(servicePrincipalName=*)"
            if self.opts.include_computers != "Yes":
                spn_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"

            command_parts = base + [
                "get",
                "search",
                "--base",
                "DOMAIN",
                "--filter",
                spn_filter,
                "--attr",
                "sAMAccountName,servicePrincipalName,adminCount,userAccountControl,msDS-SupportedEncryptionTypes",
            ]
            lines = await self._run_and_capture(command_parts)
            outputs.extend(lines)
            query_error, query_no_results = self.inspect_bloodyad_output(lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying SPN-bearing accounts; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in lines:
                lower = line.lower().strip()
                if lower.startswith("samaccountname:"):
                    spn_targets += 1
                elif (
                    lower.startswith("admincount:")
                    and line.split(":", 1)[-1].strip() == "1"
                ):
                    privileged_hits += 1
                elif lower.startswith("msds-supportedencryptiontypes:"):
                    val = self._extract_int(line)
                    if val in {0, 4}:
                        rc4_only_hits += 1

        if self.opts.include_asrep_accounts == "Yes":
            self.pane_a.write(
                "[cyan]Step 2:[/cyan] Enumerate AS-REP roastable accounts"
            )
            command_parts = base + [
                "get",
                "search",
                "--base",
                "DOMAIN",
                "--filter",
                "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                "--attr",
                "sAMAccountName,adminCount,userAccountControl,lastLogonTimestamp,pwdLastSet",
            ]
            lines = await self._run_and_capture(command_parts)
            outputs.extend(lines)
            query_error, query_no_results = self.inspect_bloodyad_output(lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying AS-REP roastable accounts; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in lines:
                lower = line.lower().strip()
                if lower.startswith("samaccountname:"):
                    asrep_targets += 1
                elif (
                    lower.startswith("admincount:")
                    and line.split(":", 1)[-1].strip() == "1"
                ):
                    privileged_hits += 1

        if self.opts.include_delegation_flags == "Yes":
            self.pane_a.write(
                "[cyan]Step 3:[/cyan] Enumerate delegation-related Kerberos targets"
            )
            command_parts = base + [
                "get",
                "search",
                "--base",
                "DOMAIN",
                "--filter",
                "(&(objectCategory=person)(objectClass=user)(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)))",
                "--attr",
                "sAMAccountName,msDS-AllowedToDelegateTo,userAccountControl,adminCount",
            ]
            lines = await self._run_and_capture(command_parts)
            outputs.extend(lines)
            query_error, query_no_results = self.inspect_bloodyad_output(lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying delegation-related targets; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in lines:
                if line.lower().strip().startswith("samaccountname:"):
                    delegation_targets += 1

        output = "\n".join(outputs)
        log_path = self.write_unique_log(output, f"kerberos_targets_{self.opts.domain}")
        if log_path:
            self.pane_a.write(
                f"✓ Saved Kerberos target enumeration output to `{log_path.name}`"
            )

        if self.opts.include_spn_accounts == "Yes":
            self.pane_a.write(f"✓ Matched {spn_targets} SPN target line(s).")
        if self.opts.include_asrep_accounts == "Yes":
            self.pane_a.write(
                f"✓ Matched {asrep_targets} AS-REP roastable target line(s)."
            )
        if self.opts.include_delegation_flags == "Yes":
            self.pane_a.write(
                f"✓ Matched {delegation_targets} delegation-flagged user line(s)."
            )

        if privileged_hits:
            self.pane_a.write(
                f"[yellow][!] Matched {privileged_hits} adminCount=1 indicator line(s) in Kerberos target output.[/yellow]"
            )
        if rc4_only_hits:
            self.pane_a.write(
                f"[yellow][!] Matched {rc4_only_hits} account line(s) with encryption type value 0/4 (RC4-only or unspecified).[/yellow]"
            )

        if had_bloodyad_error:
            self.pane_a.write(
                "[yellow][!] Kerberos target summary may be incomplete because bloodyAD reported runtime errors. Review raw output/log.[/yellow]"
            )
        elif no_result_filters and not (
            spn_targets or asrep_targets or delegation_targets
        ):
            self.pane_a.write(
                f"[cyan]Info:[/cyan] No matching Kerberos target objects were returned for {len(no_result_filters)} LDAP query filter(s)."
            )
