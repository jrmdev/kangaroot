import os
import shlex

from module import BaseModule
from tool import Tool


class TrustEnum(BaseModule):
    path = "enum/trust"
    description = "Enumerate AD trust relationships and trust directions"
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
        "transitive": {
            "default": "Yes",
            "description": "Enumerate transitive trusts when possible",
            "required": False,
            "boolean": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    @staticmethod
    def _parse_trust_line(raw_line: str):
        line = raw_line.strip()
        if "+--" not in line or ":" not in line:
            return None

        _, rhs = line.split("+--", 1)
        left, target = rhs.split(":", 1)
        target = target.strip()
        if not target:
            return None

        flags_blob = left.strip().replace("<", "").replace(">", "")
        flags = [part.strip().upper() for part in flags_blob.split("|") if part.strip()]
        if not flags:
            return None

        return target, flags

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
                "../tools/.bin/bloodyAD",
                "--host",
                self.opts.dc_hostname,
                "--dc-ip",
                self.opts.dc_ip,
            ]
            + auth_params
            + ["get", "trusts"]
        )

        if self.opts.transitive == "Yes":
            command_parts.append("--transitive")

        trust_lines = 0
        potentially_dangerous = 0
        forest_transitive_hits = 0
        unflagged_hits = 0
        lines = []
        raw_lines = []

        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            raw_lines.append(line)
            parsed = self._parse_trust_line(line)

            if parsed:
                trust_lines += 1
                target, flags = parsed

                if "FOREST_TRANSITIVE" in flags and "TREAT_AS_EXTERNAL" not in flags:
                    forest_transitive_hits += 1
                    potentially_dangerous += 1
                    line = f"[yellow]{line}[/yellow]"
                    self.pane_a.write(
                        f"[yellow][!] Potentially broad transitive forest trust: `{target}` ({'|'.join(flags)}).[/yellow]"
                    )
                elif "0" in flags and "WITHIN_FOREST" not in flags:
                    unflagged_hits += 1
                    potentially_dangerous += 1
                    line = f"[yellow]{line}[/yellow]"
                    self.pane_a.write(
                        f"[yellow][!] Trust with no explicit hardening flags reported: `{target}` ({'|'.join(flags)}).[/yellow]"
                    )
                else:
                    line = f"[cyan]{line}[/cyan]"

            self.pane_b.write(line)
            lines.append(line)

        output = "\n".join(lines)
        log_path = self.write_unique_log(output, f"trust_enum_{self.opts.domain}")
        if log_path:
            self.pane_a.write(f"✓ Saved trust enumeration output to `{log_path.name}`")

        had_bloodyad_error, no_result_filters = self.inspect_bloodyad_output(raw_lines)

        if trust_lines:
            self.pane_a.write(
                f"✓ Detected {trust_lines} trust relation line(s) in output."
            )
        if potentially_dangerous:
            self.pane_a.write(
                f"[yellow][!] Matched {potentially_dangerous} potentially dangerous trust configuration line(s) (forest transitive without TREAT_AS_EXTERNAL or no explicit hardening flags).[/yellow]"
            )
            if forest_transitive_hits:
                self.pane_a.write(
                    f"[yellow][!] {forest_transitive_hits} trust(s) are FOREST_TRANSITIVE without TREAT_AS_EXTERNAL.[/yellow]"
                )
            if unflagged_hits:
                self.pane_a.write(
                    f"[yellow][!] {unflagged_hits} trust(s) reported `0` flags; validate SID filtering and selective authentication manually.[/yellow]"
                )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, run `enum/delegation` against trusted domains and rerun `enum/acl` with `transitive=Yes` to find cross-trust control paths."
            )
        if had_bloodyad_error:
            self.pane_a.write(
                "[yellow][!] Skipping trust-enum conclusion because bloodyAD reported runtime errors. Review raw output/log.[/yellow]"
            )
        elif no_result_filters and trust_lines == 0:
            self.pane_a.write(
                f"[cyan]Info:[/cyan] No trust objects were returned for {len(no_result_filters)} LDAP query filter(s)."
            )
        elif trust_lines == 0:
            self.pane_a.write(
                "[yellow][!] No trust relation lines were matched in command output.[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, confirm privileges and connectivity, then rerun with `transitive=No` for a simpler baseline query."
            )
        elif not potentially_dangerous:
            self.pane_a.write(
                "[green]✓ No obvious dangerous trust-flag patterns were matched in parsed output.[/green]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Trusts look cleaner; next, pivot to `enum/adcs` and `enum/acl` inside each reachable domain."
            )
