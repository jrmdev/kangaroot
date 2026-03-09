import os
import sys
import re
import random
import importlib.util

from command import Command
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List, Tuple
from adutils import ADUtils
from rich.table import Table
from subprocess import check_output, CalledProcessError, STDOUT
from dataclasses import dataclass
from shutil import copy2
from tool import Tool


@dataclass
class ModuleOptions:
    def __init__(self, *args, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __str__(self):
        items = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({items})"


class BaseModule(ABC):
    """Base class for all modules"""

    # These should be set by subclasses
    path = ""
    description = ""
    options = {}

    def __init__(self, registry, job_manager):
        self.registry = registry
        self.job_manager = job_manager
        self.adutils = ADUtils()
        self.opts = ModuleOptions()
        self.env = os.environ.copy()
        self.env["PYTHONUNBUFFERED"] = "1"
        self.env["PYTHONWARNINGS"] = "ignore"
        self.env["TERM"] = "vt100"

        self.home_dir = self.get_home_dir()
        self.tool_dir = str(self.home_dir / "tools")
        self.logs_dir = str(self.home_dir / "logs")
        self.env.setdefault("UV_TOOL_DIR", os.path.join(self.tool_dir, "."))

        tool_bin_paths = []
        tools_root = Path(self.tool_dir)
        if tools_root.exists():
            preferred_tool_order = {
                "certipy-ad": 0,
                "bloodyad": 1,
                "bloodhound-ce": 2,
                "miniresponder": 3,
            }

            def tool_sort_key(path_obj: Path):
                return (preferred_tool_order.get(path_obj.name, 99), path_obj.name)

            for tool_path in sorted(tools_root.iterdir(), key=tool_sort_key):
                bin_path = tool_path / "bin"
                if bin_path.is_dir():
                    tool_bin_paths.append(str(bin_path))

        if tool_bin_paths:
            current_path = self.env.get("PATH", "")
            self.env["PATH"] = os.pathsep.join(
                tool_bin_paths + ([current_path] if current_path else [])
            )

        tool_paths = [
            os.path.join(self.tool_dir, "certipy-ad", "bin"),
            os.path.join(self.tool_dir, "krbrelayx"),
        ]
        for path in tool_paths:
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))

    def get_option_value(self, option_name: str) -> Tuple[str, str]:
        """Get option value with precedence: module -> global -> default"""
        # First check module-specific variables
        module_value = self.registry.get_module_var(self.path, option_name)
        if module_value is not None:
            return module_value, "module"

        # Then check global variables
        global_value = self.registry.get_global_var(option_name)
        if global_value is not None:
            return global_value, "global"

        # Finally use default value
        default_value = self.registry.get_option_default(self.path, option_name)
        if default_value is not None:
            return default_value, "default"

        raise ValueError(f"Option {option_name} not found")

    def set_option(self, option_name: str, value: str, is_bool: bool = False) -> bool:
        """Set a module option"""
        if option_name in self.options:
            self.registry.set_module_var(self.path, option_name, value, is_bool)
            return True
        elif (
            hasattr(self, "paired_module") and option_name in self.paired_module.options
        ):
            self.registry.set_module_var(
                self.paired_module.path, option_name, value, is_bool
            )
            return True
        return False

    def unset_option(self, option_name: str) -> bool:
        """Unset a module option"""
        if option_name in self.options:
            self.registry.unset_module_var(self.path, option_name)
            return True
        elif (
            hasattr(self, "paired_module") and option_name in self.paired_module.options
        ):
            self.registry.unset_module_var(self.paired_module.path, option_name)
            return True
        return False

    def get_options_display(self) -> List[Tuple[str, str, str, str]]:
        """Get options for display with values and sources"""
        module_name = self.name if hasattr(self, "name") else self.__class__.__name__
        table = Table(title=f"{module_name} Options")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Value")
        table.add_column("Scope")
        table.add_column("Required")
        table.add_column("Description")

        for opt_name, opt_info in self.options.items():
            try:
                value, source = self.get_option_value(opt_name)
                desc = opt_info["description"]
                required = "Yes" if opt_info["required"] else "No"
                if source == "default":
                    value = f"[dim]{value}[/dim]"
                    source = f"[dim]{source}[/dim]"
                    required = f"[dim]{required}[/dim]"
                    desc = f"[dim]{desc}[/dim]"
                elif source == "global":
                    value = f"[bold]{value}[/bold]"
                    source = f"[bold]{source}[/bold]"
                    required = f"[bold]{required}[/bold]"
                    desc = f"[bold]{desc}[/bold]"
                table.add_row(opt_name, value, source, required, desc)
            except ValueError:
                table.add_row(
                    opt_name, "NOT SET", "error", "Yes", opt_info["description"]
                )
        return table

    def validate_options(self, skip_ticket_check: bool = False) -> bool:
        """
        Validate all required module options.

        Args:
            skip_ticket_check: If True, skip checking Kerberos ticket validity

        Returns:
            True if all validations pass, False otherwise
        """
        # Rebuild normalized option values each validation pass to avoid stale state.
        self.opts = ModuleOptions()
        passed = True
        for opt_name in self.options:
            try:
                opt_val, _ = self.get_option_value(opt_name)
            except ValueError:
                opt_val = ""
                if passed:
                    passed = False
                self.pane_a.write(
                    f"[red][!] Option `{opt_name}` is not registered for module `{self.path}`. "
                    "Run module registration again.[/red]"
                )

            setattr(self.opts, opt_name, opt_val)
            if self.options[opt_name]["required"] and not opt_val:
                if passed:
                    passed = False
                self.pane_a.write(
                    f"[red][!] Option `{opt_name}` cannot be empty.[/red]"
                )

        if "auth" in self.options:
            auth = (getattr(self.opts, "auth", "") or "").strip().lower()
            auth = auth.replace("kerberos", "krb")
            if auth not in ["ntlm", "krb"]:
                if passed:
                    passed = False
                self.pane_a.write(
                    f"[red][!] Option `auth` must be 'ntlm' or 'krb'.[/red]"
                )
            else:
                setattr(self.opts, "auth", auth)

        if hasattr(self.opts, "auth") and self.opts.auth == "ntlm":
            password = (getattr(self.opts, "password", "") or "").strip()
            username = (getattr(self.opts, "username", "") or "").strip()
            domain = (getattr(self.opts, "domain", "") or "").strip()

            if password == "":
                self.pane_a.write(
                    f"[red][!] Password or NT hash is necessary for NTLM authentication.[/red]"
                )
                if passed:
                    passed = False
            if username == "":
                self.pane_a.write(
                    f"[red][!] Username is necessary for NTLM authentication.[/red]"
                )
                if passed:
                    passed = False
            if domain == "":
                self.pane_a.write(
                    f"[red][!] Domain is necessary for NTLM authentication.[/red]"
                )
                if passed:
                    passed = False

        if (
            hasattr(self.opts, "auth")
            and self.opts.auth == "krb"
            and not skip_ticket_check
        ):
            username = (getattr(self.opts, "username", "") or "").strip()
            if username == "":
                self.pane_a.write(
                    f"[red][!] Username is necessary for Kerberos authentication.[/red]"
                )
                if passed:
                    passed = False
                return passed

            fn = username.lower() + ".ccache"
            ticket = Path(self.logs_dir) / fn

            if ticket.exists():
                try:
                    ticket_validity = self.describe_ticket(ticket)
                    for line in ticket_validity:
                        if line.startswith("[*] End Time") and "(expired)" in line:
                            self.pane_a.write(
                                f"[red][!] Existing ticket for '{self.opts.username}' is expired. Request a new one before proceeding.[/red]"
                            )
                            if passed:
                                passed = False
                            break
                except Exception as e:
                    self.pane_a.write(
                        f"[yellow][!] Warning: Could not validate ticket: {e}[/yellow]"
                    )

        return passed

    def temp_ticket(self, fname, pane):
        self.env["KRB5CCNAME"] = fname
        pane.write(f"[bold]{self.path}> export KRB5CCNAME={fname}[/bold]")

    def _format_bloodyad_exception(self, line: str) -> str:
        """Condense noisy bloodyAD exception lines for pane output."""
        stripped = line.strip()
        match = re.match(
            r"^(?P<exc>[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception)):\s*(?P<msg>.*)$",
            stripped,
        )
        if not match:
            return stripped

        exc_name = match.group("exc")
        exc_short = exc_name.rsplit(".", 1)[-1]
        exc_msg = match.group("msg").strip()

        # Keep no-result responses concise and user-friendly.
        if exc_short == "NoResultError":
            return exc_msg or "No objects returned."

        if exc_msg:
            return f"{exc_short}: {exc_msg}"

        return exc_short

    async def run_command(self, command, pane):
        cmdline = f"{self.path}> " + command.replace("../tools/.bin/", "")
        pane.write(f"[bold]{cmdline}[/bold]")
        command_runner = Command(self.job_manager, self.env, pane)
        is_bloodyad_command = "bloodyad" in command.lower()
        in_bloodyad_traceback = False

        async for line in command_runner.run(command):
            if not is_bloodyad_command:
                yield line
                continue

            stripped = line.strip()

            if stripped.startswith("Traceback (most recent call last):"):
                in_bloodyad_traceback = True
                continue

            if in_bloodyad_traceback:
                if re.match(
                    r"^[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception):",
                    stripped,
                ):
                    in_bloodyad_traceback = False
                    yield self._format_bloodyad_exception(stripped)
                continue

            if re.match(
                r"^bloodyAD\.exceptions\.[A-Za-z0-9_]+:",
                stripped,
            ):
                yield self._format_bloodyad_exception(stripped)
                continue

            yield line

        if is_bloodyad_command and in_bloodyad_traceback:
            yield "BloodyADError: traceback detected"

    async def get_command_output(self, command: str):
        command_runner = Command(self.job_manager, self.env)
        return await command_runner.get_command_output(command)

    async def stream_command_output(self, command: str):
        command_runner = Command(self.job_manager, self.env)
        async for line in command_runner.stream_command_output(command):
            yield line

    def get_module_instance_from_file(self, path: str):
        spec = importlib.util.spec_from_file_location("temp_module", path)
        if spec is None or spec.loader is None:
            print("Failed to create spec")
            return

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def get_home_dir(self):
        return Path(__file__).parent

    def describe_ticket(self, ticket: Path) -> List[str]:
        """
        Run describeTicket.py and return output lines.

        Tries multiple invocation styles for compatibility across environments.
        """
        commands = [["../tools/bin/describeTicket.py", str(ticket)]]

        errors = []
        for cmd in commands:
            try:
                output = check_output(cmd, env=self.env, stderr=STDOUT).decode(
                    errors="replace"
                )
                return output.splitlines()
            except (
                FileNotFoundError,
                PermissionError,
                OSError,
                CalledProcessError,
            ) as e:
                errors.append(f"{' '.join(cmd)} -> {e}")

        raise RuntimeError("Unable to run describeTicket.py. " + " | ".join(errors))

    def parse_ticket_identity(self, ticket_info: List[str]) -> Tuple[str, str]:
        """Parse username and domain/realm from describeTicket.py output."""
        username = ""
        domain = ""

        for raw_line in ticket_info:
            line = raw_line.strip()
            if not username:
                user_match = re.search(
                    r"(?:\[\*\]\s*)?User Name\s*:\s*(.+)$", line, flags=re.IGNORECASE
                )
                if user_match:
                    username = user_match.group(1).strip()
            if not domain:
                realm_match = re.search(
                    r"(?:\[\*\]\s*)?User Realm\s*:\s*(.+)$", line, flags=re.IGNORECASE
                )
                if realm_match:
                    domain = realm_match.group(1).strip()

            if username and domain:
                break

        if not domain:
            for raw_line in ticket_info:
                line = raw_line.strip()
                realm_match = re.search(
                    r"(?:\[\*\]\s*)?Service Realm\s*:\s*(.+)$",
                    line,
                    flags=re.IGNORECASE,
                )
                if realm_match:
                    domain = realm_match.group(1).strip()
                    break

        if not username or not domain:
            raise ValueError("Unable to parse username/domain from ticket metadata.")

        if "@" in username:
            username = username.split("@", 1)[0]

        return username, domain.lower()

    def inspect_bloodyad_output(self, lines: List[str]) -> Tuple[bool, List[str]]:
        """
        Inspect bloodyAD output for traceback failures and empty-result queries.

        Returns:
            Tuple[bool, List[str]]:
                (has_fatal_error, no_result_filters)
        """
        no_result_filters = []
        saw_traceback = False
        saw_non_noresult_exception = False

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("Traceback (most recent call last):"):
                saw_traceback = True
                continue

            if "bloodyAD.exceptions.NoResultError:" in line:
                match = re.search(r"with filter:\s*(.+)$", line)
                no_result_filters.append((match.group(1) if match else line).strip())
                continue

            if line.startswith("No object found in ") and " with filter:" in line:
                match = re.search(r"with filter:\s*(.+)$", line)
                no_result_filters.append((match.group(1) if match else line).strip())
                continue

            if line.startswith("NoResultError:"):
                match = re.search(r"with filter:\s*(.+)$", line)
                no_result_filters.append((match.group(1) if match else line).strip())
                continue

            if re.search(r"bloodyAD\.exceptions\.[A-Za-z0-9_]+:", line):
                saw_non_noresult_exception = True
                continue

            if re.match(
                r"^[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception):",
                line,
            ):
                saw_non_noresult_exception = True

        has_fatal_error = saw_non_noresult_exception or (
            saw_traceback and not no_result_filters
        )
        return has_fatal_error, no_result_filters

    def ptt(self, ticket_filename: str) -> Tuple[bool, str, str, str]:
        """
        Load a ccache ticket from logs directory into current module auth settings.

        Returns:
            Tuple[bool, str, str, str]:
                (success, username, domain, canonical_ticket_name)
        """
        if not ticket_filename:
            self.pane_a.write("[red]Usage: ptt <ccache filename>[/red]")
            return False, "", "", ""

        logs_dir = Path(self.logs_dir).resolve()
        ticket = (logs_dir / ticket_filename).resolve()

        if logs_dir not in ticket.parents:
            self.pane_a.write(
                "[red]Error: ticket must be a filename inside the logs directory.[/red]"
            )
            return False, "", "", ""

        if not ticket.exists() or not ticket.is_file():
            self.pane_a.write(
                f"[red]Error: ccache not found in logs directory: {ticket_filename}[/red]"
            )
            return False, "", "", ""

        try:
            ticket_info = self.describe_ticket(ticket)
            username, domain = self.parse_ticket_identity(ticket_info)
        except Exception as e:
            self.pane_a.write(f"[red]Error: could not parse ticket metadata: {e}[/red]")
            return False, "", "", ""

        canonical_ticket = logs_dir / f"{username.lower()}.ccache"
        try:
            if ticket != canonical_ticket:
                copy2(ticket, canonical_ticket)
        except Exception as e:
            self.pane_a.write(
                f"[red]Error: could not prepare ticket for module auth: {e}[/red]"
            )
            return False, "", "", ""

        if not self.set_option("domain", domain):
            self.pane_a.write(
                "[red]Error: current module does not support 'domain' option.[/red]"
            )
            return False, "", "", ""

        if not self.set_option("username", username):
            self.pane_a.write(
                "[red]Error: current module does not support 'username' option.[/red]"
            )
            return False, "", "", ""

        if not self.set_option("auth", "krb"):
            self.pane_a.write(
                "[red]Error: current module does not support 'auth' option.[/red]"
            )
            return False, "", "", ""

        self.opts.domain = domain
        self.opts.username = username
        self.opts.auth = "krb"
        self.env["KRB5CCNAME"] = str(canonical_ticket)

        return True, username, domain, canonical_ticket.name

    async def get_tgt(self):
        """
        Request a TGT (Ticket Granting Ticket) for the current credentials.

        Returns:
            bool: True if TGT was successfully obtained, False otherwise
        """
        domain, _ = self.get_option_value("domain")
        username, _ = self.get_option_value("username")
        password, _ = self.get_option_value("password")

        if domain == "":
            self.pane_a.write(f"[red]Error: 'domain' must have a value.[/red]")
            return False

        if username == "":
            self.pane_a.write(f"[red]Error: 'username' must have a value.[/red]")
            return False

        if password == "":
            self.pane_a.write(f"[red]Error: 'password' must have a value.[/red]")
            return False

        os.chdir(self.logs_dir)
        # Skip ticket check when getting TGT
        self.validate_options(skip_ticket_check=True)

        tool = Tool(self)
        tool.set_auth(auth="ntlm", domain=domain, username=username, password=password)
        res = await tool.get_tgt_ext()

        return "Saving ticket" in res

    def auth_param_impacket(
        self, auth_type, domain, username, password, target=None, ticket=None
    ):
        if f"@{domain}" in username:
            username = username.replace(f"@{domain}", "")

        if auth_type == "krb":
            if ticket and os.path.exists(os.path.join(self.logs_dir, ticket)):
                self.env["KRB5CCNAME"] = os.path.join(self.logs_dir, ticket)
            else:
                ticket_fn = os.path.join(f"{username.lower()}.ccache")
                if not os.path.exists(ticket_fn):
                    self.pane_a.write(
                        f"[red][!] Kerberos authentication requested, but ticket missing for user {username}, request one first by typing 'tgt' or by using the kerberos/tgt module.[/red]"
                    )
                    return None
                self.env["KRB5CCNAME"] = ticket_fn

            ret = ["-k", "-no-pass"]
            if target:
                ret.append(target if ("/" in target or "@" in target) else "@" + target)
            return ret

        elif auth_type == "ntlm":
            if not password:
                self.pane_a.write("[red]Error: Password or NT hash are missing.[/red]")
                return None

            if "KRB5CCNAME" in self.env:
                del self.env["KRB5CCNAME"]

            target = "@" + target if target else ""
            if not self.is_nt_hash(password):
                return [f"{domain}/{username}:{password}{target}"]
            elif len(password):
                return ["-hashes", ":" + password, f"{domain}/{username}{target}"]

        self.pane_a.write(
            "[red]Error: invalid auth param. Check auth type, domain, username, password/hash.[/red]"
        )
        return None

    def auth_param_certipy(self, auth_type, domain, username, password, target=None):

        if f"@{domain}" in username:
            username = username.replace(f"@{domain}", "")

        if auth_type == "krb":
            ticket_fn = os.path.join(f"{username.lower()}.ccache")
            if not os.path.exists(ticket_fn):
                self.pane_a.write(
                    f"[red][!] Kerberos authentication requested, but ticket missing for user {username}, request one first by typing 'tgt' or by using the kerberos/tgt module.[/red]"
                )
                return None

            self.env["KRB5CCNAME"] = ticket_fn
            return ["-k", "-no-pass"]

        elif auth_type == "ntlm":
            if not password:
                self.pane_a.write("[red]Error: Password or NT hash are missing.[/red]")
                return None

            if "KRB5CCNAME" in self.env:
                del self.env["KRB5CCNAME"]

            if not self.is_nt_hash(password):
                return ["-u", f"{username}@{domain}", "-p", password]
            elif len(password):
                return ["-hashes", ":" + password, "-u", f"{username}@{domain}"]

        self.pane_a.write(
            "[red]Error: invalid auth param. Check auth type, domain, username, password/hash.[/red]"
        )
        return None

    def auth_param_bloodyad(self, auth_type, domain, username, password, target=None):

        if f"@{domain}" in username:
            username = username.replace(f"@{domain}", "")

        if auth_type == "krb":
            ticket_fn = os.path.join(f"{username.lower()}.ccache")
            if not os.path.exists(ticket_fn):
                self.pane_a.write(
                    f"[red][!] Kerberos authentication requested, but ticket missing for user {username}, request one first by typing 'tgt' or by using the kerberos/tgt module.[/red]"
                )
                return None

            self.env["KRB5CCNAME"] = ticket_fn
            return ["-k"]

        elif auth_type == "ntlm":
            if not password:
                self.pane_a.write("[red]Error: Password or NT hash are missing.[/red]")
                return None

            if "KRB5CCNAME" in self.env:
                del self.env["KRB5CCNAME"]

            if not self.is_nt_hash(password):
                return ["-u", username, "-d", domain, "-p", password]
            elif len(password):
                return ["-u", username, "-d", domain, "-p", ":" + password]

        self.pane_a.write(
            "[red]Error: invalid auth param. Check auth type, domain, username, password/hash.[/red]"
        )
        return None

    def auth_param_petitpotam(self, auth_type, domain, username, password, target=None):

        if f"@{domain}" in username:
            username = username.replace(f"@{domain}", "")

        if auth_type == "krb":
            ticket_fn = os.path.join(f"{username.lower()}.ccache")
            if not os.path.exists(ticket_fn):
                self.pane_a.write(
                    f"[red][!] Kerberos authentication requested, but ticket missing for user {username}, request one first by typing 'tgt' or by using the kerberos/tgt module.[/red]"
                )
                return None

            self.env["KRB5CCNAME"] = ticket_fn
            return ["-k", "-no-pass"]

        elif auth_type == "ntlm":
            if not password:
                self.pane_a.write("[red]Error: Password or NT hash are missing.[/red]")
                return None

            if "KRB5CCNAME" in self.env:
                del self.env["KRB5CCNAME"]

            if not self.is_nt_hash(password):
                return ["-u", username, "-d", domain, "-p", password]
            elif len(password):
                return ["-hashes", ":" + password, "-u", username, "-d", domain]

        self.pane_a.write(
            "[red]Error: invalid auth param. Check auth type, domain, username, password/hash.[/red]"
        )
        return None

    def is_nt_hash(self, s: str) -> bool:
        if not isinstance(s, str):
            return False
        s = s.strip(":")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", s):
            return False
        return True

    def uniq_filename(self, base, ext="pfx"):
        uniqid = hex(random.getrandbits(32))[2:]
        return f"{base}.{uniqid}.{ext}"

    def write_unique_log(self, output, base, ext="log"):
        if output is None:
            return None

        if not isinstance(output, str):
            output = str(output)

        if not output:
            return None

        logs_path = Path(self.logs_dir)
        logs_path.mkdir(parents=True, exist_ok=True)
        log_path = logs_path / self.uniq_filename(base, ext)

        with open(log_path, "w", encoding="utf-8") as f:
            f.write(output)

        return log_path

    @abstractmethod
    async def run(self):
        """Execute the module - must be implemented by subclasses"""
        pass
