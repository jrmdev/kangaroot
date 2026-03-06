import asyncio
from module import BaseModule

class ResponderCapture(BaseModule):
    path = "responder/capture"
    description = "Poison LLMNR, NBT-NS and mDNS lookups and catpure hashes"
    options = {
        "iface": {"default": "eth0", "description": "Interface to listen on", "required": True},
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)
   
    async def run(self):

        try:
            iface, _ = self.get_option_value("iface")
            async for line in self.run_command(f"miniresponder -I {iface}", self.pane_b):
                self.pane_b.write(line)

        except Exception as e:
            self.pane_b.write(f"[red]Error in module:[/red] {str(e)}")