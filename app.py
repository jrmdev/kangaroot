import asyncio
import shlex
import time

from typing import Any, List, cast
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Input, RichLog, Static
from textual.binding import Binding
from console import InteractiveConsole, ConsolePane

from rich.table import Table
from job_manager import JobManager
from registry import ModuleRegistry

__prog__ = 'kangaroot'

class MainApp(App):
    """Main application class"""

    TITLE = "Kangaroot"
    SUB_TITLE = "AD console"
    
    CSS_PATH = "app.tcss"
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+l", "clear_panes", "Clear Panes"),
    ]

    def __init__(self):
        super().__init__()
        self.mouse_enabled = True
        self.job_manager = JobManager()
        self.module_registry = ModuleRegistry()
        
    def compose(self) -> ComposeResult:
        """Compose the UI layout"""
        with ConsolePane(id="left_pane"):
            yield Static("Console", classes="pane_title")
            yield RichLog(id="console_log", markup=True, wrap=True)
            with Horizontal(id="prompt_container"):
                yield Static(f"[cyan]{__prog__} > [/cyan]", id="prompt_label")
                yield InteractiveConsole(
                    self.module_registry,
                    id="console_input"
                )
        
        # Right container
        with Vertical(id="right_pane"):
            # Top right pane (B)
            yield Static("Output 1", classes="pane_title")
            yield RichLog(id="output_b", markup=True, wrap=True)
            
            # Bottom right pane (C)
            yield Static("Output 2", classes="pane_title")
            yield RichLog(id="output_c", markup=True, wrap=True)
    
    def on_mount(self) -> None:
        """Initialize the application"""
        self.theme = "textual-dark"
        console_input = self.query_one("#console_input", InteractiveConsole)
        console_log = self.query_one("#console_log", RichLog)

        # Welcome message
        console_log.write("[bold blue]Kangaroot Console[/bold blue]")
        console_log.write("Type 'help' for available commands")
        console_log.write("Type 'list' to see all available modules")
        console_log.write("Use 'use <module_path>' to select a module")
        console_log.write("")
        
        console_input.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle command submission"""
        if event.input.id != "console_input":
            return
            
        console_input = self.query_one("#console_input", InteractiveConsole)
        console_log = self.query_one("#console_log", RichLog)
        
        command = event.value.strip()
        if not command:
            return
        
        # Add to history
        console_input.add_to_history(command)
        
        # Display command
        if console_input.current_module:
            prompt_text = f"{__prog__} ({console_input.current_module}) > "
        else:
            prompt_text = f"{__prog__} > "
        console_log.write(f"\n[cyan]{prompt_text}[/cyan]{command}")
        
        # Process command
        asyncio.create_task(self._process_command(command, console_input, console_log))
        
        # Clear input
        console_input.value = ""
    
    async def _quit(self):
        """Stop all jobs before quitting"""
        await self.job_manager.stop_all_jobs()
        self.module_registry.close()
        self.exit()

    async def _process_command(self, command: str, console_input: InteractiveConsole, console_log: RichLog):
        """Process user commands"""
        parts = shlex.split(command)
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == "jobs":
            self._show_jobs(console_log)
        elif cmd == "stop":
            await self._stop_job(args, console_log)
        elif cmd == "list":
            self._list_modules(console_log)
        elif cmd == "help":
            self._show_help(console_input, console_log)
        elif cmd == "use":
            await self._use_module(args, console_input, console_log)
        elif cmd == "run":
            await self._run_module(console_input, console_log)
        elif cmd in ["set", "setg", "unset", "unsetg"]:
            self._handle_var_commands(cmd, args, console_input, console_log)
        elif cmd == "show" or cmd == "info":
            self._show_options(console_input, console_log)
        elif cmd == "back":
            self._go_back(console_input, console_log)
        elif cmd == "clear":
            self._clear_panes()
        elif cmd == "globals":
            self._show_globals(console_log)
        elif cmd == "creds" or cmd == "cred":
            self._cred_manager(console_input, console_log, args)
        elif cmd == "tgt":
            await self._request_tgt(console_input, console_log)
        elif cmd == "ptt":
            await self._pass_the_ticket(console_input, console_log, args)
        elif cmd == "tickets":
            self._list_tickets(console_input, console_log)
        elif cmd == "exit" or cmd == "quit":
            await self._quit()
        else:
            console_log.write(f"[red]Unknown command:[/red] {cmd}")
            console_log.write("Type 'help' for available commands")
    
    def _show_jobs(self, console_log: RichLog):
        """Show running jobs"""
        running_jobs = self.job_manager.get_running_jobs()
        
        if not running_jobs:
            console_log.write("[yellow]No jobs running[/yellow]")
            return

        table = Table(title="Running Jobs")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Command")
        table.add_column("Pane")
        table.add_column("Duration")
        current_time = time.time()
        for job_id, job in running_jobs.items():
            duration = int(current_time - job['start_time'])
            cmdline = job['command'].replace(f"../tools/.bin/", "")
            table.add_row(str(job_id), cmdline, job['pane'], f"{duration}s")
        console_log.write(table)
    
    async def _stop_job(self, args: List[str], console_log: RichLog):
        """Stop a job by ID, or all jobs"""

        if len(args) == 1:
            try:
                job_ids = [int(args[0])]
            except ValueError:
                console_log.write("[red]Invalid job ID. Must be a number.[/red]")
                return
        else:
            job_ids = list(self.job_manager.get_running_jobs().keys())

        for job_id in job_ids:
            job = self.job_manager.get_job(job_id)
            if not job:
                console_log.write(f"[red]Job {job_id} not found[/red]")
                return
            
            if job['status'] != 'running':
                console_log.write(f"[yellow]Job {job_id} is not running[/yellow]")
                return
            
            success = await self.job_manager.stop_job(job_id)
            if success:
                console_log.write(f"[green]✓ Job {job_id} stopped[/green]")
                
                # Notify the pane
                if job['pane'] == "Pane B":
                    output_pane = self.query_one("#output_b", RichLog)
                else:
                    output_pane = self.query_one("#output_c", RichLog)
            else:
                console_log.write(f"[red]Failed to stop job {job_id}[/red]")

    def _list_modules(self, console_log: RichLog):
        """List all available modules"""
        modules = self.module_registry.get_all_modules()
        if not modules:
            console_log.write("[yellow]No modules found. Run with --register-modules first.[/yellow]")
            return
            
        console_log.write("[bold]Available Modules:[/bold]")
        
        # Group modules by category
        categories = {}
        for module_info in modules:
            path = module_info['path']
            parts = path.split('/')
            category = '/'.join(parts[:-1]) if len(parts) > 1 else 'root'
            
            if category not in categories:
                categories[category] = []
            categories[category].append((path, module_info['description']))
        
        # Display modules grouped by category
        for category in sorted(categories.keys()):
            console_log.write(f"\n[bold yellow]{category}/[/bold yellow]")
            for module_path, description in sorted(categories[category]):
                module_name = module_path.split('/')[-1]
                console_log.write(f"  {module_name:<20} - {description}")
    
    def _show_help(self, console_input: InteractiveConsole, console_log: RichLog):
        """Show help information"""
        if console_input.current_module:
            console_log.write("[bold]Available Commands:[/bold]")
            console_log.write("  help                - Show this help")
            console_log.write("  run                 - Execute the selected module")
            console_log.write("  set <opt> <val>     - Set module option")
            console_log.write("  setg <opt> <val>    - Set a global option")
            console_log.write("  unset <opt>         - Unset a module option")
            console_log.write("  unsetg <opt>        - Unset a global option")
            console_log.write("  cred <...>          - Manage credentials (list, add, del, use, find)")
            console_log.write("  tgt                 - Request a TGT for the current cred")
            console_log.write("  ptt <ticket.ccache> - Load a ccache from logs and switch auth to krb")
            console_log.write("  ptt list            - List available .ccache files for pass-the-ticket")
            console_log.write("  tickets             - List available .ccache files to use with `ptt`")
            console_log.write("  show                - Show module options")
            console_log.write("  back                - Go back to main menu")
            console_log.write("  jobs                - Show running jobs")
            console_log.write("  stop <id>           - Stop a job by ID")
            console_log.write("  clear               - Clear all panes")
            console_log.write("  exit                - Exit application")
        else:
            console_log.write("[bold]Available Commands:[/bold]")
            console_log.write("  help             - Show this help")
            console_log.write("  list             - List all available modules")
            console_log.write("  jobs             - Show running jobs")
            console_log.write("  cred <...>       - Manage credentials (list, add, del, use, find)")
            console_log.write("  stop <id>        - Stop a job by ID")
            console_log.write("  use <module>     - Select a module")
            console_log.write("  setg <opt> <val> - Set a global option")
            console_log.write("  unsetg <opt>     - Unset a global option")
            console_log.write("  globals          - List all global variables")
            console_log.write("  clear            - Clear all panes")
            console_log.write("  exit             - Exit application")
    
    async def _use_module(self, args: List[str], console_input: InteractiveConsole, console_log: RichLog):
        """Select a module"""
        if not args:
            console_log.write("[red]Usage:[/red] use <module_path>")
            return
        
        module_path = args[0]
        
        # Check if module is already loaded and get fresh instance
        if module_path in self.module_registry.loaded_modules:
            module_instance = self.module_registry.loaded_modules[module_path]['instance']
            console_log.write(f"[blue]Using cached module:[/blue] {module_path}")
        else:
            module_instance = await self.module_registry.load_module(module_path, self.job_manager)
        
        if module_instance:
            console_input.current_module = module_path
            console_input.module_instance = module_instance
            console_input.update_prompt()
            
            # Assign panes
            module_instance.pane_a = console_log
            module_instance.pane_b = self.query_one("#output_b", RichLog)
            module_instance.pane_c = self.query_one("#output_c", RichLog)
            
            console_log.write(f"[green]Selected module:[/green] {module_path}")
            if hasattr(module_instance, 'options') and module_instance.options:
                console_log.write("Use 'show' to see available options")
        else:
            console_log.write(f"[red]Module not found:[/red] {module_path}")
    
    async def _run_module(self, console_input: InteractiveConsole, console_log: RichLog):
        """Run the selected module"""
        if not console_input.current_module or not console_input.module_instance:
            console_log.write("[red]No module selected. Use 'use <module>' first.[/red]")
            return

        console_log.write(f"[green]Running module:[/green] {console_input.current_module}")
        module_instance = cast(Any, console_input.module_instance)
        await module_instance.run()

    async def _request_tgt(self, console_input: InteractiveConsole, console_log: RichLog):
        """Run the selected module"""
        if not console_input.current_module or not console_input.module_instance:
            console_log.write("[red]No module selected. Use 'use <module>' first.[/red]")
            return

        module = cast(Any, console_input.module_instance)
        paired = getattr(module, 'paired_module', None)

        options = module.options
        paired_options = paired.options if paired else {}

        if not options.get("username", None) and not paired_options.get("username", None):
            console_log.write("[red]This module doesn't require credentials.[/red]")
            return

        if options.get("username", None):
            if await module.get_tgt():
                console_log.write(f"[green]✓ Obtained TGT for {module.opts.username}@{module.opts.domain}[/green]")
                return

        elif paired_options.get("username", None):
            if paired is None:
                console_log.write("[red]Error obtaining TGT. Check credentials.[/red]")
                return
            paired.pane_a = console_log
            paired.pane_b = self.query_one("#output_b", RichLog)
            paired.pane_c = self.query_one("#output_c", RichLog)
            if await paired.get_tgt():
                console_log.write(f"[green]✓ Obtained TGT for {paired.opts.username}@{paired.opts.domain}[/green]")
                return

        console_log.write("[red]Error obtaining TGT. Check credentials.[/red]")

    async def _pass_the_ticket(self, console_input: InteractiveConsole, console_log: RichLog, args: List[str]):
        """Load a ccache file into current module auth settings (krb)."""
        if not console_input.current_module or not console_input.module_instance:
            console_log.write("[red]No module selected. Use 'use <module>' first.[/red]")
            return

        if len(args) == 1 and args[0].lower() == "list":
            self._list_tickets(console_input, console_log)
            return

        if len(args) != 1:
            console_log.write("[red]Usage:[/red] ptt <ccache filename|list>")
            return

        module = cast(Any, console_input.module_instance)
        paired = getattr(module, 'paired_module', None)

        options = module.options
        paired_options = paired.options if paired else {}

        if not options.get("username", None) and not paired_options.get("username", None):
            console_log.write("[red]This module doesn't require credentials.[/red]")
            return

        target_module = cast(Any, module if options.get("username", None) else paired)
        if not target_module:
            console_log.write("[red]Error: unable to resolve credential-bearing module.[/red]")
            return

        if target_module is paired:
            target_module.pane_a = console_log
            target_module.pane_b = self.query_one("#output_b", RichLog)
            target_module.pane_c = self.query_one("#output_c", RichLog)

        success, username, domain, ticket_name = target_module.ptt(args[0])
        if success:
            console_log.write(f"[green]Loaded ticket {ticket_name} for {username}@{domain}; auth set to krb[/green]")

    def _list_tickets(self, console_input: InteractiveConsole, console_log: RichLog):
        """List available ccache files in logs directory."""
        if not console_input.current_module or not console_input.module_instance:
            console_log.write("[red]No module selected. Use 'use <module>' first.[/red]")
            return

        module = cast(Any, console_input.module_instance)
        paired = getattr(module, 'paired_module', None)
        options = module.options
        paired_options = paired.options if paired else {}

        if not options.get("username", None) and not paired_options.get("username", None):
            console_log.write("[red]This module doesn't require credentials.[/red]")
            return

        target_module = cast(Any, module if options.get("username", None) else paired)
        if not target_module:
            console_log.write("[red]Error: unable to resolve credential-bearing module.[/red]")
            return

        tickets = sorted(Path(target_module.logs_dir).glob("*.ccache"), key=lambda p: p.name.lower())
        if not tickets:
            console_log.write("[yellow]No .ccache files found in logs directory.[/yellow]")
            return

        console_log.write("[bold]Available Kerberos tickets:[/bold]")
        for ticket in tickets:
            console_log.write(f"  {ticket.name}")
    
    def _handle_var_commands(self, cmd: str, args: List[str], console_input: InteractiveConsole, console_log: RichLog):
        """Handle set/setg/unset/unsetg commands"""
        if cmd == "set":
            if args and args[0] == 'cred' and len(args) > 1:
                self._cred_manager(console_input, console_log, args[1:])
            else:
                self._set_option(args, console_input, console_log)
        elif cmd == "setg":
            self._set_global_option(args, console_log)
        elif cmd == "unset":
            self._unset_option(args, console_input, console_log)
        elif cmd == "unsetg":
            self._unset_global_option(args, console_log)
    
    def _set_option(self, args: List[str], console_input: InteractiveConsole, console_log: RichLog):
        """Set module option"""
        if not console_input.module_instance:
            console_log.write("[red]No module selected. Use 'use <module>' first.[/red]")
            return

        module_instance = cast(Any, console_input.module_instance)
        
        if len(args) < 2:
            console_log.write("[red]Usage:[/red] set <option> <value>")
            return
        
        option_name = args[0]
        option_value = " ".join(args[1:])
        
        is_bool = False
        if option_name in module_instance.options:
            if module_instance.options[option_name].get("boolean", False) == True:
                is_bool = True

        if module_instance.set_option(option_name, option_value, is_bool):
            console_log.write(f"[green]Set {option_name} => {option_value}[/green]")
        else:
            console_log.write(f"[red]Unknown option:[/red] {option_name}")
    
    def _set_global_option(self, args: List[str], console_log: RichLog):
        """Set global option"""
        if len(args) < 2:
            console_log.write("[red]Usage:[/red] setg <option> <value>")
            return
        
        option_name = args[0]
        option_value = " ".join(args[1:])
        
        self.module_registry.set_global_var(option_name, option_value)
        console_log.write(f"[green]Set global {option_name} => {option_value}[/green]")
    
    def _unset_option(self, args: List[str], console_input: InteractiveConsole, console_log: RichLog):
        """Unset module option"""
        if not console_input.module_instance:
            console_log.write("[red]No module selected.[/red]")
            return

        module_instance = cast(Any, console_input.module_instance)
        
        if not args:
            console_log.write("[red]Usage:[/red] unset <option>")
            return
        
        option_name = args[0]
        
        if module_instance.unset_option(option_name):
            console_log.write(f"[green]Unset {option_name}[/green]")
        else:
            console_log.write(f"[red]Unknown option:[/red] {option_name}")
    
    def _unset_global_option(self, args: List[str], console_log: RichLog):
        """Unset global option"""
        if not args:
            console_log.write("[red]Usage:[/red] unsetg <option>")
            return
        
        option_name = args[0]
        
        self.module_registry.unset_global_var(option_name)
        console_log.write(f"[green]Unset global {option_name}[/green]")
    
    def _show_options(self, console_input: InteractiveConsole, console_log: RichLog):
        """Show module options"""
        if not console_input.module_instance:
            console_log.write("[red]No module selected. Use 'use <module>' first.[/red]")
            return

        module = cast(Any, console_input.module_instance)
        console_log.write(f"[bold]{module.description}[/bold]")

        if hasattr(module, 'info'):
            console_log.write(f"\n{module.info}")
        
        console_log.write("\n")
        console_log.write(module.get_options_display())

        paired_module = getattr(module, 'paired_module', None)
        if paired_module:
            console_log.write("\n")
            console_log.write(paired_module.get_options_display())
        
        if "username" in module.options and "domain" in module.options:
            console_log.write("Hint: type 'cred <id>' to set credentials to use with this module.")
 
    def _go_back(self, console_input: InteractiveConsole, console_log: RichLog):
        """Go back to main menu"""
        console_input.current_module = None
        console_input.module_instance = None
        console_input.update_prompt()
        console_log.write("[green]Back to main menu[/green]")
    
    def _clear_panes(self) -> None:
        """Clear all output panes"""
        output_a = self.query_one("#console_log", RichLog)
        output_b = self.query_one("#output_b", RichLog)
        output_c = self.query_one("#output_c", RichLog)
        output_a.clear()
        output_b.clear()
        output_c.clear()

    def _show_globals(self, console_log: RichLog):
        """Show all global variables"""
        globals_dict = self.module_registry.get_all_globals()
        if not globals_dict:
            console_log.write("[yellow]No global variables set[/yellow]")
        else:
            table = Table(title="Global Variables")
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Value")
            for name, val in sorted(globals_dict.items()):
                table.add_row(name, str(val))
            console_log.write(table)

    def _cred_manager(self, console_input: InteractiveConsole, console_log: RichLog, args: List[str]):
        """
        Manage credentials. Possible options are:
        list [cred_id]
        add <domain> <username> <password or nt hash>
        del <cred_id>
        use <cred_id>
        """
        
        if args == []:
            args = ['list']

        command = args[0].lower()
        
        if command == 'list':
            # Handle optional cred_id parameter
            cred_id = None
            if len(args) > 1:
                try:
                    cred_id = int(args[1])
                except ValueError:
                    console_log.write("[red]Error: Invalid credential ID. Must be a number.[/red]")
                    return
            
            credentials = self.module_registry.list_credentials(cred_id)
            if not credentials:
                if cred_id:
                    console_log.write(f"[yellow]No credential found with ID {cred_id}[/yellow]")
                else:
                    console_log.write("[yellow]No credentials stored[/yellow]")
            else:
                table = Table(title="Stored Credentials")
                table.add_column("ID", style="cyan", no_wrap=True)
                table.add_column("Domain", style="green")
                table.add_column("Username", style="blue")
                table.add_column("Password", style="dim")
                table.add_column("NT Hash", style="dim")
                
                for cred in credentials:
                    table.add_row(
                        str(cred['id']),
                        cred['domain'],
                        cred['username'],
                        cred['password'],
                        cred['nthash']
                    )
                console_log.write(table)
        
        elif command == 'add':
            if len(args) != 4:
                console_log.write("[red]Error: add command requires 3 arguments: <domain> <username> <password_or_nthash>[/red]")
                return
            
            domain, username, password_or_nthash = args[1], args[2], args[3]

            try:
                cred_id = self.module_registry.add_credential(domain, username, password_or_nthash)
                if cred_id > 0:
                    console_log.write(f"[green]✓ Credential added successfully with ID {cred_id}[/green]")
                else:
                    console_log.write(f"[red]Credential already exists.[/red]")

            except Exception as e:
                console_log.write(f"[red]Error adding credential: {str(e)}[/red]")
        
        elif command == 'del':
            if len(args) != 2:
                console_log.write("[red]Error: del command requires 1 argument: <cred_id>[/red]")
                return
            
            try:
                cred_id = int(args[1])
            except ValueError:
                console_log.write("[red]Error: Invalid credential ID. Must be a number.[/red]")
                return
            
            try:
                if self.module_registry.delete_credential(cred_id):
                    console_log.write(f"[green]✓ Credential {cred_id} deleted successfully[/green]")
                else:
                    console_log.write(f"[yellow]No credential found with ID {cred_id}[/yellow]")
            except Exception as e:
                console_log.write(f"[red]Error deleting credential: {str(e)}[/red]")

        elif command == 'find':
            if len(args) != 2:
                console_log.write("[red]Error: find command requires 1 argument: <str>[/red]")
                return

            credentials = self.module_registry.find_credentials(args[1])
            if not credentials:
                console_log.write("[yellow]No credentials found matching the search term.[/yellow]")
            else:
                table = Table(title="Stored Credentials")
                table.add_column("ID", style="cyan", no_wrap=True)
                table.add_column("Domain", style="green")
                table.add_column("Username", style="blue")
                table.add_column("Password", style="dim")
                table.add_column("NT Hash", style="dim")
                
                for cred in credentials:
                    table.add_row(
                        str(cred['id']),
                        cred['domain'],
                        cred['username'],
                        cred['password'],
                        cred['nthash']
                    )
                console_log.write(table)

        elif command.isdigit():
            if not console_input.module_instance:
                console_log.write("[red]No module selected. Use 'use <module>' first.[/red]")
                return

            module_instance = cast(Any, console_input.module_instance)

            cred_id = int(command)
            cred = self.module_registry.get_credentials(cred_id)
            if not cred:
                console_log.write(f"[red]Error: Credential ID {cred_id} not found.[/red]")
                return
            domain, username, password = cred
            module_instance.set_option('domain', domain)
            module_instance.set_option('username', username)
            module_instance.set_option('password', password)
            module_instance.set_option('auth', 'ntlm')
            console_log.write(f"[green]✓ Using credentials for {username}@{domain}[/green]")

        else:
            console_log.write(f"[red]Error: Unknown command '{command}'. Use 'list', 'add', or 'del'[/red]")
