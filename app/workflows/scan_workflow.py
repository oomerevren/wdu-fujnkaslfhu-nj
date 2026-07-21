
import asyncio
from .activities import ScanActivities

class PentestWorkflow:
    def __init__(self):
        self.activities = ScanActivities()
        self.state = "IDLE"

    async def run(self, target: str):
        print(f"[Workflow] Starting autonomous pentest for: {target}")
        self.state = "RUNNING"
        
        try:
            # Phase 1: Recon
            recon_res = await self.activities.run_recon(target)
            
            # Phase 2: Scan
            scan_res = await self.activities.run_vulnerability_scan(recon_res)
            
            # Phase 3: Exploit
            exploit_res = await self.activities.run_exploitation(scan_res)
            
            self.state = "COMPLETED"
            print("[Workflow] Pentest completed successfully.")
            return {"target": target, "result": exploit_res, "status": self.state}
            
        except Exception as e:
            self.state = "FAILED"
            print(f"[Workflow] Critical error: {e}")
            return {"status": self.state, "error": str(e)}
