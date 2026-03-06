from textual.containers import Vertical
from textual.widgets import Input, RichLog, Static
from textual.binding import Binding
from textual.events import Click, Key
from textual import events
from typing import Any, cast

__prog__ = 'kangaroot'

class ConsolePane(Vertical):
    async def on_click(self, event: Click) -> None:
        # Let RichLog widgets handle click/drag events for text selection.
        if isinstance(event.widget, RichLog):
            return

        input_widget = self.app.query_one("#console_input")
        input_widget.focus()
        event.stop()

class InteractiveConsole(Input):
    """Enhanced input widget with tab completion and history"""
    
    BINDINGS = [
        Binding("tab", "tab_complete", "Tab Complete", show=False),
    ]
    
    def __init__(self, module_registry, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.module_registry = module_registry
        self.history = self.module_registry.load_history()  # Load from database
        self.history_index = -1
        self.current_module: str | None = None
        self.module_instance: Any | None = None
        self.completion_suggestions = []
        self.completion_index = 0
        self.original_value = ""
        self.select_on_focus = False

    def update_prompt(self):
        """Update the prompt based on current module"""
        try:
            app = self.app
            if app:
                prompt_label = app.query_one("#prompt_label", Static)
                if self.current_module:
                    prompt_label.update(f"[cyan]{__prog__} ({self.current_module}) >[/cyan] ")
                else:
                    prompt_label.update(f"[cyan]{__prog__} >[/cyan] ")
        except Exception:
            pass  # Ignore if elements not found

    def action_tab_complete(self) -> None:
        """Handle tab completion action"""
        self._handle_tab_completion()
    
    def on_key(self, event: events.Key) -> None:
        """Handle special keys for history and tab completion"""
        if event.key == "up":
            self._history_previous()
            event.prevent_default()
        elif event.key == "down":
            self._history_next()
            event.prevent_default()
        else:
            # Reset completion state on other keys (except tab)
            if event.key != "tab":
                self.completion_suggestions = []
                self.completion_index = 0
        
    def _history_previous(self):
        """Navigate to previous command in history"""
        if self.history and self.history_index > 0:
            self.history_index -= 1
            self.value = self.history[self.history_index]
            self.cursor_position = len(self.value)
        elif self.history and self.history_index == -1:
            self.history_index = len(self.history) - 1
            self.value = self.history[self.history_index]
            self.cursor_position = len(self.value)

    def _history_next(self):
        """Navigate to next command in history"""
        if self.history and self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.value = self.history[self.history_index]
            self.cursor_position = len(self.value)
        elif self.history_index >= 0:
            self.history_index = -1
            self.value = ""
            self.cursor_position = 0
    
    def _handle_tab_completion(self):
        """Handle tab completion for commands"""
        current_value = self.value.strip()
        
        # If no suggestions yet, generate them
        if not self.completion_suggestions:
            self.original_value = current_value
            
            if current_value.startswith("use "):
                # Tab completion for module names
                partial = current_value[4:].strip()  # Remove "use "
                all_matching = self.module_registry.get_module_suggestions(partial)
                completion_parts = set()
                for m in all_matching:
                    suffix = m[len(partial):]
                    if suffix:
                        if '/' in suffix:
                            seg = suffix.split('/')[0] + '/'
                        else:
                            seg = suffix
                        completion_parts.add(seg)
                completed_modules = [partial + p for p in sorted(completion_parts)]
                self.completion_suggestions = [f"use {cm}" for cm in completed_modules if completed_modules]
            elif current_value.startswith("set "):
                # Tab completion for option names
                if self.module_instance:
                    module = cast(Any, self.module_instance)
                    options = list(module.options.keys())
                    partial = current_value[4:].split()[0] if len(current_value[4:].split()) > 0 else ""
                    matching_options = [opt for opt in options if opt.startswith(partial)]
                    self.completion_suggestions = [f"set {opt}" for opt in matching_options]
            elif current_value.startswith("unset "):
                # Tab completion for option names in module
                if self.module_instance:
                    module = cast(Any, self.module_instance)
                    options = list(module.options.keys())
                    partial = current_value[6:].split()[0] if len(current_value[6:].split()) > 0 else ""
                    matching_options = [opt for opt in options if opt.startswith(partial)]
                    self.completion_suggestions = [f"unset {opt}" for opt in matching_options]
            elif current_value.startswith("setg "):
                # Tab completion for all known options
                partial = current_value[5:].split()[0] if len(current_value[5:].split()) > 0 else ""
                all_options = self.module_registry.get_all_option_names()
                matching_options = [opt for opt in sorted(all_options) if opt.startswith(partial)]
                self.completion_suggestions = [f"setg {opt}" for opt in matching_options]
            elif current_value.startswith("unsetg "):
                # Tab completion for all known options
                partial = current_value[7:].split()[0] if len(current_value[7:].split()) > 0 else ""
                all_options = self.module_registry.get_all_option_names()
                matching_options = [opt for opt in sorted(all_options) if opt.startswith(partial)]
                self.completion_suggestions = [f"unsetg {opt}" for opt in matching_options]
            else:
                # Basic command completion
                commands = ["use", "run", "set", "setg", "show", "info", "back", "help", "exit", "list", "jobs", "stop", "unset", "unsetg", "globals", "clear", "cred", "tgt", "ptt"]
                matching = [cmd for cmd in commands if cmd.startswith(current_value)]
                self.completion_suggestions = matching
        
        # Cycle through suggestions
        if self.completion_suggestions:
            completed_text = self.completion_suggestions[self.completion_index]
            self.value = completed_text
            # Move cursor to the end of the completed text
            self.cursor_position = len(completed_text)
            self.completion_index = (self.completion_index + 1) % len(self.completion_suggestions)
            
            # If only one suggestion and it ends with '/', clear suggestions to allow sub-completion on next tab
            if len(self.completion_suggestions) == 1 and completed_text.endswith('/'):
                self.completion_suggestions = []
                self.completion_index = 0
    
    def add_to_history(self, command: str):
        """Add command to history"""
        if command and (not self.history or self.history[-1] != command):
            self.history.append(command)
            self.module_registry.add_to_history(command)  # Save to database
        self.history_index = -1
