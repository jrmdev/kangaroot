import os
import shlex

from module import BaseModule
from tool import Tool


class ADIDNSEnum(BaseModule):
    path = "enum/dns_adidns"
    description = "Enumerate AD-integrated DNS records and highlight risky entries"
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
        "zone": {
            "default": "",
            "description": "Optional DNS zone to enumerate (empty = all zones)",
            "required": False,
        },
        "include_system_records": {
            "default": "No",
            "description": "Include system records such as _ldap/_kerberos/@",
            "required": False,
            "boolean": True,
        },
        "transitive": {
            "default": "No",
            "description": "Traverse trusted domains for broader DNS enumeration",
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

        auth_params = tool.get_auth_params("bloodyad")
        if not auth_params:
            return

        command_parts = (
            [
                "bloodyAD",
                "--host",
                self.opts.dc_hostname,
                "--dc-ip",
                self.opts.dc_ip,
            ]
            + auth_params
            + ["get", "dnsDump"]
        )

        if self.opts.zone:
            command_parts += ["--zone", self.opts.zone]
        if self.opts.include_system_records != "Yes":
            command_parts.append("--no-detail")
        if self.opts.transitive == "Yes":
            command_parts.append("--transitive")

        outputs = []
        risky_hits = 0
        risky_markers = ("wpad", "isatap", "autodiscover")

        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            lower = line.lower()
            wildcard_hit = (
                "name: *" in lower
                or "record: *" in lower
                or lower.strip().startswith("*.")
            )
            if any(marker in lower for marker in risky_markers) or wildcard_hit:
                line = f"[yellow]{line}[/yellow]"
                risky_hits += 1

            self.pane_b.write(line)
            outputs.append(line)

        output = "\n".join(outputs)
        log_path = self.write_unique_log(output, f"adidns_enum_{self.opts.domain}")
        if log_path:
            self.pane_a.write(f"✓ Saved ADIDNS enumeration output to `{log_path.name}`")

        had_bloodyad_error, no_result_filters = self.inspect_bloodyad_output(outputs)

        if risky_hits:
            self.pane_a.write(
                f"[yellow][!] Matched {risky_hits} potentially risky DNS line(s) (WPAD/wildcard/ISATAP/autodiscover).[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, verify if risky records are writable via `enum/acl` and consider coercion+relay paths (`coercion/*` with `adcs/esc8_ntlm`)."
            )
        if had_bloodyad_error:
            self.pane_a.write(
                "[yellow][!] Skipping clean DNS-risk conclusion because bloodyAD reported runtime errors. Review raw output/log.[/yellow]"
            )
        elif no_result_filters and not risky_hits:
            self.pane_a.write(
                f"[cyan]Info:[/cyan] No DNS records were returned for {len(no_result_filters)} LDAP query filter(s)."
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, retry with a specific `zone` value or enable `include_system_records=Yes` for fuller visibility."
            )
        elif not risky_hits:
            self.pane_a.write(
                "[green]✓ No risky DNS keyword matches were found in parsed output.[/green]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] DNS looks cleaner here; next, pivot to `enum/trust` or `enum/delegation` for lateral movement opportunities."
            )
