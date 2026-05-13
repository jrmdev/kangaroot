#!/usr/bin/env python3
import argparse
import asyncio
import logging
import sys
from contextlib import contextmanager
from typing import Any, Iterable

from rich.console import Console
from rich.errors import MarkupError
from rich.markup import escape
from rich.table import Table

from job_manager import JobManager
from logging_config import setup_logging
from registry import ModuleRegistry


logger = logging.getLogger(__name__)

EXAMPLES = """examples:
  uv run cli.py --list
  uv run cli.py --register-modules
  uv run cli.py -m enum/adcs --show
  uv run cli.py --cred list
  uv run cli.py --cred list 3
  uv run cli.py --cred add corp.local alice 'Password123!'
  uv run cli.py --cred update corp.local alice aad3b435b51404eeaad3b435b51404ee
  uv run cli.py --cred del 3
  uv run cli.py -m enum/adcs --use-cred 3 dc_ip=10.0.0.10
  uv run cli.py -m adcs/esc8_ntlm ca_host=10.1.1.1 dc_ip=10.2.2.2 template=DomainController coercer=petitpotam
"""


class CliRegistry(ModuleRegistry):
    """ModuleRegistry with process-local module option overrides for CLI runs."""

    def __init__(self):
        super().__init__()
        self._cli_module_vars: dict[tuple[str, str], str] = {}
        self._persist_module_writes = True

    @contextmanager
    def cli_writes(self):
        old_value = self._persist_module_writes
        self._persist_module_writes = False
        try:
            yield
        finally:
            self._persist_module_writes = old_value

    def set_module_var(
        self, module_path: str, var: str, val: str, is_bool: bool = False
    ):
        if self._persist_module_writes:
            return super().set_module_var(module_path, var, val, is_bool)
        self.set_cli_module_var(module_path, var, val, is_bool)
        return None

    def unset_module_var(self, module_path: str, var: str):
        if self._persist_module_writes:
            return super().unset_module_var(module_path, var)
        self._cli_module_vars.pop((module_path, var), None)
        return None

    def get_module_var(self, module_path: str, var: str):
        key = (module_path, var)
        if key in self._cli_module_vars:
            return self._cli_module_vars[key]
        return super().get_module_var(module_path, var)

    def set_cli_module_var(
        self, module_path: str, var: str, val: str, is_bool: bool = False
    ):
        if is_bool:
            val = self._to_bool_str(val)
        self._cli_module_vars[(module_path, var)] = val

    def apply_cli_credential(
        self, module_path: str, domain: str, username: str, password: str
    ):
        self.set_cli_module_var(module_path, "domain", domain)
        self.set_cli_module_var(module_path, "username", username)
        self.set_cli_module_var(module_path, "password", password)
        self.set_cli_module_var(module_path, "auth", "ntlm")


class CliPane:
    """Small RichLog-like adapter used by existing modules."""

    def __init__(self, console: Console, pane_id: str, label: str = ""):
        self.console = console
        self.id = pane_id
        self.label = label

    def write(self, value: Any):
        if self.label and isinstance(value, str):
            self._print(f"[dim]{escape(self.label)}[/dim] {value}")
            return
        self._print(value)

    def _print(self, value: Any):
        try:
            self.console.print(value)
        except MarkupError:
            self.console.print(escape(value) if isinstance(value, str) else value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Kangaroot CLI - run registered AD operation modules without the TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )
    parser.add_argument(
        "-m",
        "--module",
        dest="module_path",
        help="registered module path to use, e.g. adcs/esc8_ntlm",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        dest="list_modules",
        help="list registered modules and exit",
    )
    parser.add_argument(
        "-s",
        "--show",
        action="store_true",
        help="show module options and exit; requires -m/--module",
    )
    parser.add_argument(
        "-c",
        "--cred",
        choices=["add", "del", "list", "update"],
        help="manage stored credentials",
    )
    parser.add_argument(
        "-u",
        "--use-cred",
        type=int,
        help="credential ID to apply to a module for this run; requires -m/--module",
    )
    parser.add_argument(
        "--register-modules",
        action="store_true",
        help="register modules from disk and exit",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="module execution timeout in seconds; default: 300",
    )
    parser.add_argument(
        "--no-timeout",
        action="store_true",
        help="disable module execution timeout",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="set logging level",
    )
    parser.add_argument(
        "items",
        nargs="*",
        help="module options as key=value, or arguments for --cred",
    )
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.show and not args.module_path:
        parser.error("--show requires -m/--module")

    if args.use_cred is not None and not args.module_path:
        parser.error("--use-cred requires -m/--module")

    if args.cred:
        _validate_cred_args(parser, args.cred, args.items)
        return

    maintenance_mode = args.list_modules or args.register_modules
    if maintenance_mode:
        return

    if not args.module_path:
        parser.error("module execution requires -m/--module")

    for item in args.items:
        if "=" not in item or item.startswith("="):
            parser.error(f"module options must use key=value syntax: {item}")


def _validate_cred_args(
    parser: argparse.ArgumentParser, command: str, items: list[str]
) -> None:
    if command == "list":
        if len(items) > 1:
            parser.error("--cred list accepts at most one credential ID")
        if items:
            _parse_int(parser, items[0], "credential ID")
        return

    if command == "del":
        if len(items) != 1:
            parser.error("--cred del requires: <cred_id>")
        _parse_int(parser, items[0], "credential ID")
        return

    if command in {"add", "update"}:
        if len(items) != 3:
            parser.error(f"--cred {command} requires: <domain> <username> <password_or_nthash>")
        return


def _parse_int(parser: argparse.ArgumentParser, value: str, label: str) -> int:
    try:
        return int(value)
    except ValueError:
        parser.error(f"{label} must be a number: {value}")
        raise


def parse_module_options(items: Iterable[str]) -> list[tuple[str, str]]:
    options = []
    for item in items:
        key, value = item.split("=", 1)
        options.append((key, value))
    return options


def split_coercer_items(items: list[str]) -> tuple[list[str], list[str]]:
    early = []
    remaining = []
    for item in items:
        key, _ = item.split("=", 1)
        if key == "coercer":
            early.append(item)
        else:
            remaining.append(item)
    return early, remaining


def list_modules(registry: ModuleRegistry, console: Console) -> None:
    modules = registry.get_all_modules()
    if not modules:
        console.print("[yellow]No modules registered. Run with --register-modules first.[/yellow]")
        return

    table = Table(title=f"Registered Modules ({len(modules)})")
    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Description")

    for module in modules:
        table.add_row(module["path"], module["description"])

    console.print(table)


def register_modules(registry: ModuleRegistry, console: Console) -> int:
    registry.register_modules_from_disk()
    console.print("[green]Modules registered successfully[/green]")
    return 0


def show_module(module: Any, pane: CliPane) -> None:
    pane.write(f"[bold]{module.description}[/bold]")
    info = getattr(module, "info", "")
    if info:
        pane.write("")
        pane.write(info)
    pane.write("")
    pane.write(module.get_options_display())

    paired_module = getattr(module, "paired_module", None)
    if paired_module:
        pane.write("")
        pane.write(paired_module.get_options_display())


def handle_credentials(
    registry: ModuleRegistry, console: Console, command: str, items: list[str]
) -> int:
    if command == "list":
        cred_id = int(items[0]) if items else None
        credentials = registry.list_credentials(cred_id)
        if not credentials:
            if cred_id is None:
                console.print("[yellow]No credentials stored[/yellow]")
            else:
                console.print(f"[yellow]No credential found with ID {cred_id}[/yellow]")
            return 0
        _print_credentials(console, credentials)
        return 0

    if command == "add":
        domain, username, secret = items
        cred_id = registry.add_credential(domain, username, secret)
        if cred_id > 0:
            console.print(f"[green]Credential added with ID {cred_id}[/green]")
            return 0
        if cred_id == 0:
            console.print("[red]Credential already exists[/red]")
            return 1
        console.print("[red]Error adding credential[/red]")
        return 1

    if command == "update":
        domain, username, secret = items
        action, cred_id = registry.upsert_credential(domain, username, secret)
        if action == "error":
            console.print("[red]Error updating credential[/red]")
            return 1
        console.print(f"[green]Credential {action} with ID {cred_id}[/green]")
        return 0

    if command == "del":
        cred_id = int(items[0])
        if registry.delete_credential(cred_id):
            console.print(f"[green]Credential {cred_id} deleted[/green]")
            return 0
        console.print(f"[yellow]No credential found with ID {cred_id}[/yellow]")
        return 1

    console.print(f"[red]Unknown credential command: {command}[/red]")
    return 1


def _print_credentials(console: Console, credentials: list[dict[str, Any]]) -> None:
    table = Table(title="Stored Credentials")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Domain", style="green")
    table.add_column("Username", style="blue")
    table.add_column("Password", style="dim")
    table.add_column("NT Hash", style="dim")

    for cred in credentials:
        table.add_row(
            str(cred["id"]),
            cred["domain"],
            cred["username"],
            cred["password"],
            cred["nthash"],
        )

    console.print(table)


async def load_cli_module(
    registry: CliRegistry,
    job_manager: JobManager,
    module_path: str,
    console: Console,
):
    module = await registry.load_module(module_path, job_manager)
    if not module:
        console.print(f"[red]Module not found:[/red] {module_path}")
        return None

    assign_panes(module, console)
    return module


def assign_panes(module: Any, console: Console) -> None:
    pane_a = CliPane(console, "console_log")
    pane_b = CliPane(console, "output_b", "output 1")
    pane_c = CliPane(console, "output_c", "output 2")

    module.pane_a = pane_a
    module.pane_b = pane_b
    module.pane_c = pane_c

    paired = getattr(module, "paired_module", None)
    if paired:
        paired.pane_a = pane_a
        paired.pane_b = pane_b
        paired.pane_c = pane_c


def apply_module_options(module: Any, registry: CliRegistry, items: list[str]) -> bool:
    options = parse_module_options(items)

    with registry.cli_writes():
        for option_name, option_value in options:
            if not _set_module_option(module, option_name, option_value):
                return False
            assign_panes(module, module.pane_a.console)

    return True


def apply_credential(module: Any, registry: CliRegistry, cred_id: int) -> bool:
    credential = registry.get_credentials(cred_id)
    if not credential:
        module.pane_a.write(f"[red]Error: Credential ID {cred_id} not found.[/red]")
        return False

    domain, username, password = credential
    applied = False

    with registry.cli_writes():
        for option_name, option_value in (
            ("domain", domain),
            ("username", username),
            ("password", password),
            ("auth", "ntlm"),
        ):
            if _set_module_option(module, option_name, option_value):
                applied = True
            assign_panes(module, module.pane_a.console)

    if not applied:
        module.pane_a.write("[red]Error: current module does not support credentials.[/red]")
        return False

    module.pane_a.write(f"[green]Using credentials for {username}@{domain}[/green]")
    return True


def _set_module_option(module: Any, option_name: str, option_value: str) -> bool:
    is_bool = False
    if option_name in getattr(module, "options", {}):
        is_bool = module.options[option_name].get("boolean", False) is True

    if module.set_option(option_name, option_value, is_bool):
        return True

    module.pane_a.write(f"[red]Unknown option:[/red] {option_name}")
    return False


async def run_module(module: Any, job_manager: JobManager, timeout: float | None) -> int:
    try:
        if timeout is None:
            await module.run()
        else:
            await asyncio.wait_for(module.run(), timeout=timeout)
        return 0
    except asyncio.TimeoutError:
        module.pane_a.write(f"[red]Module timed out after {timeout:g} seconds.[/red]")
        await job_manager.stop_all_jobs()
        return 124
    except Exception as exc:
        module.pane_a.write(f"[red]Unhandled module error:[/red] {exc}")
        await job_manager.stop_all_jobs()
        logger.exception("Unhandled module error")
        return 1
    finally:
        await job_manager.stop_all_jobs()


async def async_main(args: argparse.Namespace, console: Console) -> int:
    registry = CliRegistry()
    job_manager = JobManager()
    try:
        if args.register_modules:
            return register_modules(registry, console)

        if args.list_modules:
            list_modules(registry, console)
            return 0

        if args.cred:
            return handle_credentials(registry, console, args.cred, args.items)

        module = await load_cli_module(registry, job_manager, args.module_path, console)
        if module is None:
            return 1

        early_items, remaining_items = split_coercer_items(args.items)

        if early_items and not apply_module_options(module, registry, early_items):
            return 1

        if args.use_cred is not None and not apply_credential(module, registry, args.use_cred):
            return 1

        if remaining_items and not apply_module_options(module, registry, remaining_items):
            return 1

        if args.show:
            show_module(module, module.pane_a)
            return 0

        module.pane_a.write(f"[green]Running module:[/green] {args.module_path}")
        timeout = None if args.no_timeout else args.timeout
        return await run_module(module, job_manager, timeout)
    finally:
        registry.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    setup_logging(log_level=args.log_level)
    console = Console()

    try:
        return asyncio.run(async_main(args, console))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
