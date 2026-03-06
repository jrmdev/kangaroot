"""
Job management for running background processes
"""
import asyncio
import time
from typing import Dict, Optional

class JobManager:
    """Manages running jobs and their processes"""
   
    def __init__(self):
        self.jobs = {}  # job_id -> job_info
        self.next_job_id = 1
   
    def add_job(self, command: str, process, pane_name: str) -> int:
        """Add a job to the manager"""
        job_id = self.next_job_id
        self.next_job_id += 1
       
        self.jobs[job_id] = {
            'id': job_id,
            'command': command,
            'process': process,
            'pane': pane_name,
            'start_time': time.time(),
            'status': 'running'
        }
        return job_id
   
    def remove_job(self, job_id: int):
        """Remove a job from the manager"""
        if job_id in self.jobs:
            del self.jobs[job_id]
   
    def get_job(self, job_id: int) -> Optional[Dict]:
        """Get job by ID"""
        return self.jobs.get(job_id)
   
    def get_running_jobs(self) -> Dict:
        """Get all running jobs"""
        return {jid: job for jid, job in self.jobs.items() if job['status'] == 'running'}

    async def stop_job_by_name(self, command: str) -> bool:
        for jid, job in self.get_running_jobs().items():
            if command in job['command']:
                return await self.stop_job(jid)
        return False

    async def stop_job(self, job_id: int) -> bool:
        """Stop a job by ID"""
        job = self.jobs.get(job_id)
        if not job or job['status'] != 'running':
            return False
       
        process = job['process']
        if not process:
            job['status'] = 'stopped'
            return True
        
        # Check if process is still alive (works for both subprocess and ptyprocess)
        if hasattr(process, 'isalive'):
            # PtyProcess
            if not process.isalive():
                job['status'] = 'stopped'
                return True
        elif hasattr(process, 'returncode'):
            # subprocess.Popen
            if process.returncode is not None:
                job['status'] = 'stopped'
                return True
        
        try:
            # Terminate the process
            if hasattr(process, 'terminate') and callable(getattr(process, 'terminate')):
                if hasattr(process, 'isalive'):
                    # PtyProcess - terminate with optional force
                    process.terminate(force=False)
                    
                    # Wait for graceful termination
                    try:
                        await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=2.0)
                    except asyncio.TimeoutError:
                        # Force kill if graceful termination failed
                        process.terminate(force=True)
                        try:
                            await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass  # Process might be already dead
                else:
                    # subprocess.Popen
                    process.terminate()
                    
                    # Wait for graceful termination
                    try:
                        await asyncio.wait_for(process.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        # Force kill if graceful termination failed
                        process.kill()
                        try:
                            await asyncio.wait_for(process.wait(), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass  # Process might be already dead
            
            # Mark as stopped regardless of cleanup success
            job['status'] = 'stopped'
            return True
            
        except Exception:
            # Even if termination failed, mark as stopped to prevent retries
            job['status'] = 'stopped'
            return True  # Return True since we attempted to stop it
    
    async def stop_all_jobs(self):
        """Stop all running jobs"""
        tasks = []
        for job_id in list(self.jobs.keys()):
            if self.jobs[job_id]['status'] == 'running':
                tasks.append(self.stop_job(job_id))
       
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)