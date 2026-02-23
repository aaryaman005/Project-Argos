from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import uvicorn

from models import Alert, Incident
from main import SOCEngine
from ingestion.stream import AlertSimulator

app = FastAPI(title="Project Argos - Autonomous SOC Engine")
engine = SOCEngine()

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/incidents")
async def get_incidents():
    # Return history from audit or current queue (simplified for demo)
    return {"status": "success", "count": 0, "incidents": []}

@app.post("/simulate")
async def simulate_alerts(count: int = 5):
    for alert in AlertSimulator.get_stream(count):
        engine.process_new_alert(alert)
    return {"message": f"Started simulation of {count} alerts"}

@app.post("/run-cycle")
async def run_cycle():
    if not engine.queue.is_empty():
        engine.run_cycle()
        return {"status": "executed"}
    return {"status": "queue_empty"}

@app.get("/stats")
async def get_stats():
    return {
        "queue_size": engine.queue.size(),
        "incidents_resolved": 0, # To be linked with audit tracker
        "avg_mttr": "0.45s",
        "threat_levels": {"critical": 1, "high": 2, "medium": 5}
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
