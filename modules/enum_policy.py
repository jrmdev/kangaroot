import os
import re
import shlex

from module import BaseModule
from tool import Tool


class DomainPolicyEnum(BaseModule):
    path = "enum/policy"
    description = "Enumerate default domain password policy, FGPP, and MAQ"
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
        "include_domain_policy": {
            "default": "Yes",
            "description": "Enumerate default domain password and lockout policy",
            "required": False,
            "boolean": True,
        },
        "include_fgpp": {
            "default": "Yes",
            "description": "Enumerate Fine-Grained Password Policies (PSOs)",
            "required": False,
            "boolean": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    def _domain_to_dn(self, domain: str) -> str:
        return ",".join(f"DC={part}" for part in domain.split(".") if part)

    def _extract_int(self, line: str):
        match = re.search(r"(-?\d+)", line)
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

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

        findings = set()
        outputs = []
        pso_count = 0
        parsed_policy_values = 0
        had_bloodyad_error = False
        no_result_filters = set()
        weak_maq = False
        weak_password_policy = False
        step = 1

        if self.opts.include_domain_policy == "Yes":
            self.pane_a.write(
                f"[cyan]Step {step}:[/cyan] Enumerate default domain policy"
            )
            step += 1
            attrs = (
                "distinguishedName,ms-DS-MachineAccountQuota,minPwdLength,"
                "pwdHistoryLength,maxPwdAge,minPwdAge,lockoutThreshold,"
                "lockOutObservationWindow,lockoutDuration,pwdProperties"
            )
            command_parts = base + [
                "get",
                "search",
                "--base",
                "DOMAIN",
                "--filter",
                "(objectClass=domainDNS)",
                "--attr",
                attrs,
            ]
            policy_lines = await self._run_and_capture(command_parts)
            outputs.extend(policy_lines)
            query_error, query_no_results = self.inspect_bloodyad_output(policy_lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying the default domain policy; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in policy_lines:
                lower = line.lower()
                if "ms-ds-machineaccountquota" in lower:
                    parsed_policy_values += 1
                    val = self._extract_int(line)
                    if val is not None and val > 0:
                        weak_maq = True
                        findings.add(
                            f"[yellow][!] ms-DS-MachineAccountQuota is {val} (>0), regular users may add machine accounts.[/yellow]"
                        )
                elif "minpwdlength" in lower:
                    parsed_policy_values += 1
                    val = self._extract_int(line)
                    if val is not None and val < 12:
                        weak_password_policy = True
                        findings.add(
                            f"[yellow][!] Minimum password length is {val} (<12).[/yellow]"
                        )
                elif "lockoutthreshold" in lower:
                    parsed_policy_values += 1
                    val = self._extract_int(line)
                    if val is not None and val == 0:
                        weak_password_policy = True
                        findings.add(
                            "[yellow][!] Account lockout threshold is 0 (no lockout policy).[/yellow]"
                        )

        if self.opts.include_fgpp == "Yes":
            self.pane_a.write(
                f"[cyan]Step {step}:[/cyan] Enumerate fine-grained password policies"
            )
            fgpp_base = f"CN=Password Settings Container,CN=System,{self._domain_to_dn(self.opts.domain)}"
            attrs = (
                "cn,msDS-PasswordSettingsPrecedence,msDS-MinimumPasswordLength,"
                "msDS-PasswordHistoryLength,msDS-MaximumPasswordAge,msDS-LockoutThreshold,"
                "msDS-LockoutObservationWindow,msDS-LockoutDuration,msDS-PSOAppliesTo"
            )
            command_parts = base + [
                "get",
                "search",
                "--base",
                fgpp_base,
                "--filter",
                "(objectClass=msDS-PasswordSettings)",
                "--attr",
                attrs,
            ]

            fgpp_lines = await self._run_and_capture(command_parts)
            outputs.extend(fgpp_lines)
            query_error, query_no_results = self.inspect_bloodyad_output(fgpp_lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying fine-grained password policies; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in fgpp_lines:
                lower = line.lower()
                if lower.strip().startswith("cn:"):
                    pso_count += 1
                if "msds-minimumpasswordlength" in lower:
                    parsed_policy_values += 1
                    val = self._extract_int(line)
                    if val is not None and val < 12:
                        weak_password_policy = True
                        findings.add(
                            f"[yellow][!] FGPP minimum password length is {val} (<12).[/yellow]"
                        )
                elif "msds-lockoutthreshold" in lower:
                    parsed_policy_values += 1
                    val = self._extract_int(line)
                    if val is not None and val == 0:
                        weak_password_policy = True
                        findings.add(
                            "[yellow][!] FGPP lockout threshold is 0 for at least one PSO.[/yellow]"
                        )

        output = "\n".join(outputs)
        log_path = self.write_unique_log(output, f"domain_policy_{self.opts.domain}")
        if log_path:
            self.pane_a.write(f"✓ Saved domain policy output to `{log_path.name}`")

        if self.opts.include_fgpp == "Yes":
            self.pane_a.write(
                f"✓ Discovered {pso_count} fine-grained password policy object(s)."
            )

        if findings:
            for finding in sorted(findings):
                self.pane_a.write(finding)
            hints = []
            if weak_maq:
                hints.append("`delegation/rbcd`")
            if weak_password_policy:
                hints.extend(["`kerberos/asreproast`", "`kerberos/kerberoast`"])
            if hints:
                self.pane_a.write(
                    f"[cyan]Tip:[/cyan] Next, validate policy-driven attack paths with {', '.join(dict.fromkeys(hints))}."
                )
        if had_bloodyad_error:
            self.pane_a.write(
                "[yellow][!] Skipping clean policy-risk conclusion because bloodyAD reported runtime errors. Review raw output/log.[/yellow]"
            )
        elif not findings and no_result_filters and parsed_policy_values == 0:
            self.pane_a.write(
                f"[cyan]Info:[/cyan] No matching domain policy objects were returned for {len(no_result_filters)} LDAP query filter(s)."
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, verify directory read scope and rerun with both `include_domain_policy` and `include_fgpp` enabled."
            )
        elif not findings:
            self.pane_a.write(
                "[green]✓ No obvious weak MAQ/password/lockout indicators were matched in parsed output.[/green]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Policy checks look cleaner; next, pivot to `enum/acl` and `enum/adcs` for misconfiguration-based escalation paths."
            )
