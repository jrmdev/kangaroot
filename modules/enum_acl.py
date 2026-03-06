import os
import shlex

from tool import Tool
from module import BaseModule


class ACLEnum(BaseModule):
    path = "enum/acl"
    description = "Enumerate potentially exploitable AD ACL misconfigurations via writable objects"
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
        "object_type": {
            "default": "*",
            "description": "Object type filter for writable search (e.g. user, group, computer, ou)",
            "required": False,
        },
        "right": {
            "default": "ALL",
            "description": "Right type to search (ALL, WRITE, CHILD)",
            "required": False,
        },
        "partition": {
            "default": "ALL",
            "description": "Directory partition to explore (DOMAIN, CONFIGURATION, SCHEMA, DNS, ALL)",
            "required": False,
        },
        "detail": {
            "default": "Yes",
            "description": "Show writable attributes/object types for each object",
            "required": False,
            "boolean": True,
        },
        "transitive": {
            "default": "No",
            "description": "Traverse trusts for broader writable-object coverage",
            "required": False,
            "boolean": True,
        },
        "exclude_deleted": {
            "default": "Yes",
            "description": "Exclude deleted objects from results",
            "required": False,
            "boolean": True,
        },
        "bloodhound": {
            "default": "No",
            "description": "Create BloodHound-compatible ZIP from writable objects",
            "required": False,
            "boolean": True,
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

        right = (self.opts.right or "ALL").upper()
        partition = (self.opts.partition or "ALL").upper()

        if right not in {"ALL", "WRITE", "CHILD"}:
            self.pane_a.write(
                "[red][!] Option `right` must be one of: ALL, WRITE, CHILD.[/red]"
            )
            return

        if partition not in {"DOMAIN", "CONFIGURATION", "SCHEMA", "DNS", "ALL"}:
            self.pane_a.write(
                "[red][!] Option `partition` must be one of: DOMAIN, CONFIGURATION, SCHEMA, DNS, ALL.[/red]"
            )
            return

        tool.title("Enumerate writable objects and ACL-derived attack paths")

        auth_params = tool.get_auth_params("bloodyad")
        if not auth_params:
            return

        cmd_parts = (
            [
                "bloodyAD",
                "--host",
                self.opts.dc_hostname,
                "--dc-ip",
                self.opts.dc_ip,
            ]
            + auth_params
            + [
                "get",
                "writable",
                "--otype",
                self.opts.object_type or "*",
                "--right",
                right,
                "--partition",
                partition,
            ]
        )

        if self.opts.detail == "Yes":
            cmd_parts.append("--detail")
        if self.opts.transitive == "Yes":
            cmd_parts.append("--transitive")
        if self.opts.exclude_deleted == "Yes":
            cmd_parts.append("--exclude-del")
        if self.opts.bloodhound == "Yes":
            cmd_parts.append("--bh")

        lines = []
        high_impact_hits = 0
        keywords = (
            "genericall",
            "genericwrite",
            "writedacl",
            "writeowner",
            "all extended rights",
            "forcechangepassword",
            "resetpassword",
            "writespn",
            "writemembers",
            "shadowcredentials",
            "addself",
        )

        async for line in self.run_command(shlex.join(cmd_parts), self.pane_b):
            lower_line = line.lower()
            if any(keyword in lower_line for keyword in keywords):
                line = f"[yellow]{line}[/yellow]"
                high_impact_hits += 1

            self.pane_b.write(line)
            lines.append(line)

        output = "\n".join(lines)
        log_path = self.write_unique_log(output, f"acl_enum_{self.opts.domain}")
        if log_path:
            self.pane_a.write(f"✓ Saved ACL enumeration output to `{log_path.name}`")

        had_bloodyad_error, no_result_filters = self.inspect_bloodyad_output(lines)

        if high_impact_hits:
            self.pane_a.write(
                f"✓ Found {high_impact_hits} high-impact ACL indicators (GenericAll/GenericWrite/WriteDACL/etc.)."
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Pivot with `acl/shadowcreds`, `acl/setpasswd`, `acl/setspn`, or `acl/writedacl` as appropriate."
            )
        if had_bloodyad_error:
            self.pane_a.write(
                "[yellow][!] Skipping clean ACL-risk conclusion because bloodyAD reported runtime errors. Review raw output/log.[/yellow]"
            )
        elif no_result_filters and not high_impact_hits:
            self.pane_a.write(
                f"[cyan]Info:[/cyan] No writable-object results were returned for {len(no_result_filters)} LDAP query filter(s)."
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, retry with broader scope (`object_type=*`, `partition=ALL`, `transitive=Yes`) or a higher-privilege account."
            )
        elif not high_impact_hits:
            self.pane_a.write(
                "[yellow][!] No obvious high-impact ACL indicators were matched in command output.[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, pivot to `enum/privileged` and `enum/adcs` for non-ACL escalation opportunities."
            )
