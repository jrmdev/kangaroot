import os
import re
import shlex

from pathlib import Path

from module import BaseModule


class LDAPHardening(BaseModule):
    path = "enum/ldaps"
    description = "Enumerate LDAP signing and LDAPS channel binding posture"
    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP or DNS resolver for domain SRV lookups. If blank, a domain DC is resolved automatically.",
            "required": False,
        },
        "domain": {
            "default": "",
            "description": "Target domain name (FQDN)",
            "required": True,
        },
        "timeout": {
            "default": "10",
            "description": "DNS timeout in seconds used by CheckLDAPStatus",
            "required": False,
        },
        "debug": {
            "default": "No",
            "description": "Enable debug output in CheckLDAPStatus",
            "required": False,
            "boolean": True,
        },
        "ts": {
            "default": "No",
            "description": "Add timestamps to CheckLDAPStatus output",
            "required": False,
            "boolean": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def run(self):
        if not self.validate_options(skip_ticket_check=True):
            return

        os.chdir(self.logs_dir)

        dc_ip = self.adutils.get_dc_ip(self.opts.dc_ip, self.opts.domain)
        if not dc_ip:
            self.pane_a.write(
                "[red][!] Could not determine a DC IP for LDAP hardening checks.[/red]"
            )
            return

        command_parts = [
            "timeout",
            "5",
            "../tools/.bin/CheckLDAPStatus.py",
            "-dc-ip",
            dc_ip,
            "-domain",
            self.opts.domain,
            "-timeout",
            self.opts.timeout,
        ]
        if self.opts.debug == "Yes":
            command_parts.append("-debug")
        if self.opts.ts == "Yes":
            command_parts.append("-ts")

        outputs = []
        current_host = ""
        enumerated_hosts = 0
        weak_signing_hosts = set()
        weak_cbt_hosts = set()
        saw_traceback = False
        tool_errors = []

        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            stripped = line.strip()
            lower = stripped.lower()

            if stripped.startswith("Hostname:"):
                current_host = stripped.split(":", 1)[-1].strip()
                enumerated_hosts += 1

            if stripped.startswith("Traceback (most recent call last):"):
                saw_traceback = True
            elif saw_traceback and re.match(
                r"^[A-Za-z_][A-Za-z0-9_]*(?:Error|Exception):", stripped
            ):
                tool_errors.append(stripped)

            if "ldap signing required:" in lower:
                status = stripped.split(":", 1)[-1].strip().lower()
                if status in {"false", "no", "0"} and current_host:
                    weak_signing_hosts.add(current_host)
                    line = f"[yellow]{line}[/yellow]"

            elif "ldaps channel binding status:" in lower:
                status = stripped.split(":", 1)[-1].strip().lower()
                if (
                    status in {"never", "when supported", "no tls cert"}
                    and current_host
                ):
                    weak_cbt_hosts.add(current_host)
                    line = f"[yellow]{line}[/yellow]"

            self.pane_b.write(line)
            outputs.append(line)

        output = "\n".join(outputs)
        log_path = self.write_unique_log(output, f"ldap_hardening_{self.opts.domain}")
        if log_path:
            self.pane_a.write(f"✓ Saved LDAP hardening output to `{log_path.name}`")

        if tool_errors or saw_traceback:
            detail = tool_errors[-1] if tool_errors else "traceback detected"
            self.pane_a.write(
                f"[yellow][!] CheckLDAPStatus returned an error (`{detail}`). Skipping posture conclusion.[/yellow]"
            )
            return

        if enumerated_hosts == 0:
            self.pane_a.write(
                "[yellow][!] No domain controllers were returned by CheckLDAPStatus. Skipping posture conclusion.[/yellow]"
            )
            return

        if weak_signing_hosts:
            self.pane_a.write(
                f"[yellow][!] LDAP signing not required on {len(weak_signing_hosts)} DC(s).[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, evaluate NTLM relay/coercion paths (`coercion/*`) against hosts where signing is not required."
            )
        else:
            self.pane_a.write(
                "[green]✓ LDAP signing appears required on enumerated DCs.[/green]"
            )

        if weak_cbt_hosts:
            self.pane_a.write(
                f"[yellow][!] LDAPS channel binding is not set to Always on {len(weak_cbt_hosts)} DC(s).[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, prioritize relay-resistant checks and ADCS relay testing with `adcs/esc8_ntlm` where feasible."
            )
        else:
            self.pane_a.write(
                "[green]✓ LDAPS channel binding appears set to Always on enumerated DCs.[/green]"
            )

        if not weak_signing_hosts and not weak_cbt_hosts:
            self.pane_a.write(
                "[cyan]Tip:[/cyan] LDAP hardening looks strong; next, pivot to `enum/adcs`, `enum/acl`, and Kerberos-focused paths."
            )
