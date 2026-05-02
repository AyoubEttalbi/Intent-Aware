import uuid
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from agent.loop import AgentLoop
from db.models import init_db, SessionLocal, Job, Bug

init_db()

app = FastAPI(title="Intent-Aware QA Agent API")

class AnalysisRequest(BaseModel):
    spec_url: str
    description: str
    base_url: str
    source_dir: Optional[str] = "."
    max_assumptions: Optional[int] = 2
    crawl_ui: Optional[bool] = False

class AnalysisResponse(BaseModel):
    job_id: str
    status: str

async def run_analysis_task(job_id: str, request: AnalysisRequest):
    db = SessionLocal()
    try:
        loop = AgentLoop(request.spec_url, request.description, request.base_url)
        results = await loop.run(
            max_assumptions=request.max_assumptions, 
            crawl_ui=request.crawl_ui,
            source_dir=request.source_dir
        )
        
        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = "completed"
            job.results = results
            job.completed_at = datetime.utcnow()
            
            # Save individual bugs for easy querying
            for r in results:
                if r['check'].get('is_bug'):
                    bug = Bug(
                        job_id=job_id,
                        severity=r['check'].get('severity'),
                        reason=r['check'].get('reason'),
                        scenario_name=r['scenario'].get('name'),
                        endpoint=r['scenario'].get('endpoint'),
                        method=r['scenario'].get('method'),
                        reproduction_json=r['scenario'],
                        response_data=r['response']
                    )
                    db.add(bug)
            
            db.commit()
    except Exception as e:
        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = "failed"
            job.error = str(e)
            db.commit()
    finally:
        db.close()

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    db = SessionLocal()
    
    new_job = Job(
        id=job_id,
        spec_url=request.spec_url,
        base_url=request.base_url,
        description=request.description,
        status="pending"
    )
    db.add(new_job)
    db.commit()
    db.close()
    
    background_tasks.add_task(run_analysis_task, job_id, request)
    
    return {"job_id": job_id, "status": "pending"}

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    db = SessionLocal()
    job = db.query(Job).filter(Job.id == job_id).first()
    db.close()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return {
        "job_id": job.id,
        "status": job.status,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "results": job.results,
        "error": job.error
    }

@app.get("/")
async def root():
    return {"message": "Intent-Aware QA Agent API is running."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
