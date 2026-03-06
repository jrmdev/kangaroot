import os
import shlex

from module import BaseModule
from tool import Tool


class PrivilegedEnum(BaseModule):
    path = "enum/privileged"
    description = (
        "Enumerate privileged groups, nested members, and adminCount=1 objects"
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
        "include_admincount": {
            "default": "Yes",
            "description": "Enumerate objects protected by AdminSDHolder (adminCount=1)",
            "required": False,
            "boolean": True,
        },
        "include_groups": {
            "default": "Yes",
            "description": "Enumerate members of high-privilege built-in groups",
            "required": False,
            "boolean": True,
        },
        "group_list": {
            "default": "Domain Admins,Enterprise Admins,Schema Admins,Administrators,DnsAdmins,Account Operators,Backup Operators,Server Operators,Print Operators,Group Policy Creator Owners,Cert Publishers",
            "description": "Comma-separated groups to enumerate",
            "required": False,
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
            "../tools/.bin/bloodyAD",
            "--host",
            self.opts.dc_hostname,
            "--dc-ip",
            self.opts.dc_ip,
        ] + auth_params

        outputs = []
        admincount_hits = 0
        member_hits = 0
        had_bloodyad_error = False
        no_result_filters = set()
        step = 1

        if self.opts.include_admincount == "Yes":
            self.pane_a.write(
                f"[cyan]Step {step}:[/cyan] Enumerate adminCount=1 objects"
            )
            step += 1
            command_parts = base + [
                "get",
                "search",
                "--base",
                "DOMAIN",
                "--filter",
                "(adminCount=1)",
                "--attr",
                "sAMAccountName,objectClass,distinguishedName,adminCount,lastLogonTimestamp",
            ]
            lines = await self._run_and_capture(command_parts)
            outputs.extend(lines)
            query_error, query_no_results = self.inspect_bloodyad_output(lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying adminCount=1 objects; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in lines:
                if line.lower().strip().startswith("samaccountname:"):
                    admincount_hits += 1

        if self.opts.include_groups == "Yes":
            groups = [
                item.strip() for item in self.opts.group_list.split(",") if item.strip()
            ]
            for group in groups:
                self.pane_a.write(
                    f"[cyan]Step {step}:[/cyan] Enumerate members of `{group}`"
                )
                step += 1
                command_parts = base + [
                    "get",
                    "object",
                    group,
                    "--attr",
                    "distinguishedName,member",
                ]
                lines = await self._run_and_capture(command_parts)
                outputs.extend(lines)
                query_error, query_no_results = self.inspect_bloodyad_output(lines)
                if query_error:
                    had_bloodyad_error = True
                    self.pane_a.write(
                        f"[yellow][!] bloodyAD returned an error while querying members of `{group}`; results may be incomplete.[/yellow]"
                    )
                no_result_filters.update(query_no_results)

                for line in lines:
                    if line.lower().strip().startswith("member:"):
                        member_hits += 1

        output = "\n".join(outputs)
        log_path = self.write_unique_log(output, f"privileged_enum_{self.opts.domain}")
        if log_path:
            self.pane_a.write(
                f"✓ Saved privileged enumeration output to `{log_path.name}`"
            )

        if self.opts.include_admincount == "Yes":
            self.pane_a.write(f"✓ Found {admincount_hits} adminCount=1 object line(s).")
        if self.opts.include_groups == "Yes":
            self.pane_a.write(f"✓ Found {member_hits} privileged group member line(s).")

        if had_bloodyad_error:
            self.pane_a.write(
                "[yellow][!] Skipping clean privileged-enum conclusion because bloodyAD reported runtime errors. Review raw output/log.[/yellow]"
            )
        elif no_result_filters and admincount_hits == 0 and member_hits == 0:
            self.pane_a.write(
                f"[cyan]Info:[/cyan] No matching privileged objects were returned for {len(no_result_filters)} LDAP query filter(s)."
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, verify group names for this domain and retry with a custom `group_list`."
            )
        elif admincount_hits == 0 and member_hits == 0:
            self.pane_a.write(
                "[yellow][!] No privileged entries were matched from parsed output. Review raw output/log for environment-specific formats.[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, try `enum/acl` to find delegated control paths that do not require built-in privileged groups."
            )
        else:
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, focus on high-value principals with `kerberos/targets`, then chain access using `enum/acl`."
            )
