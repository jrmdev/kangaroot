import os

from module import BaseModule
from tool import Tool

class ResponderCapture(BaseModule):
    path = "responder/capture"
    description = "Poison LLMNR, NBT-NS and mDNS lookups and catpure hashes"
    options = {
        "iface": {"default": "eth0", "description": "Interface to listen on", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    @staticmethod
    def _is_running_as_root() -> bool:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        if hasattr(os, "getuid"):
            return os.getuid() == 0
        return False
   
    async def run(self):
        try:
            if not self.validate_options():
                return

            if not self._is_running_as_root():
                self.pane_a.write(
                    "[red][!] This module must be run as root to use MiniResponder.[/red]"
                )
                return

            tool = Tool(self)
            tool.set_output_pane(self.pane_b)
            await tool.miniresponder(self.opts.iface)

        except Exception as e:
            self.pane_b.write(f"[red]Error in module:[/red] {str(e)}")
