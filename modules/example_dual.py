import asyncio
from module import BaseModule

class ExampleModule(BaseModule):
    """Ping two addresses simultaneously"""
   
    path = "example/dual_cmd"
    description = "Example module - Ping two addresses simultaneously"
    options = {
        "ip1": {"default": "127.0.0.1", "description": "First IP address", "required": True},
        "ip2": {"default": "127.0.0.2", "description": "Second IP address", "required": True},
        "count": {"default": "4", "description": "Number of pings", "required": True}
    }
    
    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)
   
    async def run(self):
        if not self.validate_options():
            return

        # Example: run a command and print the output to a pane (not streamed):
        #out = await self.get_command_output("ls -l --color")
        #self.pane_b.write(out)

        # Example: run a command, collect output lines and stream to a pane:
        #async for line in self.run_command("ping -c 4 127.0.0.5", self.pane_b):
        #    self.pane_b.write(line)

        # Example: build commands from module options and run in both panes concurrently.
        # output lines can be processed in a helper function
        # each process will run in its own PTY
        try:           
            cmd1 = f"ping -c {self.opts.count} {self.opts.ip1}"
            cmd2 = f"ping -c {self.opts.count} {self.opts.ip2}"
           
            # Do something with incoming output lines
            async def _run_in_pane(command: str, pane):
                async for line in self.run_command(command, pane):
                    pane.write(line)

            # Run both commands concurrently
            await asyncio.gather(
                _run_in_pane(cmd1, self.pane_b),
                _run_in_pane(cmd2, self.pane_c)
            )
           
        except Exception as e:
            self.pane_b.write(f"[red]Error in double ping module:[/red] {str(e)}")
            self.pane_c.write(f"[red]Error in double ping module:[/red] {str(e)}")
