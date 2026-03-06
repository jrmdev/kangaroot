import asyncio
import ptyprocess
import shlex
import select
import re

from typing import AsyncGenerator

class Command():

    def __init__(self, job_manager, env, pane=None):
        self.job_manager = job_manager
        self.env = env
        self.pane = pane
        self.pane_name = self.get_pane_name(pane) if pane else ""

    async def run(self, command: str) -> AsyncGenerator[str, None]:
        """Execute a command using pty, stream output, and yield lines for processing"""

        proc = None
        job_id = None

        try:
            # Spawn PTY process
            proc = ptyprocess.PtyProcess.spawn(shlex.split(command), env=self.env)
            fd = proc.fd
            
            job_id = self.job_manager.add_job(command, proc, self.pane_name)
            
            auto_confirm_patterns = [b"? (y/", b"[y/n]", b"(y/N)", b"(Y/n)"]
            buffer = b''
            
            # Main processing loop
            while proc.isalive():
                # Check if job was stopped
                job = self.job_manager.get_job(job_id)
                if not job or job['status'] != 'running':
                    proc.terminate(force=True)
                    break

                # Read data from PTY
                ready, _, _ = select.select([fd], [], [], 0.05)
                if ready:
                    try:
                        data = proc.read()
                        if not data:
                            continue

                        # Handle auto-confirmation
                        if any(pattern in data.lower() for pattern in auto_confirm_patterns):
                            proc.write(b"y\n")

                        # Process output lines
                        buffer += data
                        lines = buffer.split(b'\n')
                        buffer = lines[-1]  # Keep incomplete line

                        # Yield complete lines
                        for line in lines[:-1]:
                            cleaned_line = self._process_line(line)
                            if cleaned_line:
                                yield cleaned_line
                                
                    except (OSError, EOFError):
                        break
                else:
                    # No data available, small sleep
                    await asyncio.sleep(0.02)
            
            # Read remaining data after process ends
            async for remaining_line in self._read_remaining_data(proc, buffer, fd):
                yield remaining_line
            
            # Process final buffer content
            if buffer:
                cleaned_line = self._process_line(buffer)
                if cleaned_line:
                    yield cleaned_line

            # Wait for process completion
            if proc.isalive():
                proc.wait()

            # Display job status
            self._display_job_status(job_id)
            
        except Exception as e:
            if self.pane:
                self.pane.write(f"[red]Error executing command:[/red] {str(e)}")
        finally:
            self._cleanup(proc, job_id)

    async def get_command_output(self, command: str) -> str:
        """Execute a quick command and return output without adding to job manager"""
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, bufsize=0, env=self.env)
        
        stdout_data, _ = await proc.communicate()
        
        if stdout_data:
            decoded_output = stdout_data.decode('utf-8', errors='replace')
            cleaned_output = self.strip_ansi_codes(decoded_output)
            lines = [line.rstrip() for line in cleaned_output.split('\n') if line.strip()]
            
            return "\n".join(lines)
        
        return ""

    async def stream_command_output(self, command: str) -> AsyncGenerator[str, None]:
        """Execute a quick command and stream output without adding to job manager"""
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, bufsize=0, env=self.env)

        if proc.stdout:
            async for line in proc.stdout:
                decoded_line = line.decode('utf-8', errors='replace').rstrip()
                decoded_line = self.strip_ansi_codes(decoded_line)
                if decoded_line:
                    yield decoded_line
        await proc.wait()

    def _process_line(self, line: bytes) -> str:
        """Decode and clean a line of output"""
        decoded_line = line.decode('utf-8', errors='replace').rstrip()
        if decoded_line:
            return self.strip_ansi_codes(decoded_line)
        return ""

    async def _read_remaining_data(self, proc, buffer: bytes, fd):
        """Read any remaining data after process ends"""
        try:
            while True:
                ready, _, _ = select.select([fd], [], [], 0.1)
                if not ready:
                    break
                
                data = proc.read()
                if not data:
                    break
                
                buffer += data
                lines = buffer.split(b'\n')
                buffer = lines[-1]
                
                for line in lines[:-1]:
                    cleaned_line = self._process_line(line)
                    if cleaned_line:
                        yield cleaned_line
        except (OSError, EOFError):
            pass

    def _display_job_status(self, job_id):
        """Display final job status message"""
        job = self.job_manager.get_job(job_id)
        if job and self.pane:
            if job['status'] == 'stopped':
                self.pane.write(f"[yellow]Job {job_id} was stopped[/yellow]")
            elif job['status'] == 'running':
                job['status'] = 'completed'
                self.pane.write(f"[cyan]Job {job_id} completed[/cyan]\n")

    def _cleanup(self, proc, job_id):
        """Clean up process and job resources"""
        if proc:
            if proc.isalive():
                proc.terminate(force=True)
        
        if job_id is not None:
            self.job_manager.remove_job(job_id)

    def get_pane_name(self, pane):
        pane_name = pane.id if hasattr(pane, 'id') else "Unknown Pane"
        if pane_name == "output_b":
            pane_name = 'Output 1'
        elif pane_name == "output_c":
            pane_name = 'Output 2'
        return pane_name

    def strip_ansi_codes(self, text):
        return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)
