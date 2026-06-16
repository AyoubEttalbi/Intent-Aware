import os
import glob
import shutil
import time
import uuid
import threading
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from agent.engine import SecurityEngine
from agent.llm import claude_chat
from db.models import init_db, SessionLocal, Job, Bug

init_db()

app = FastAPI(title="Intent-Aware QA Agent API")

class AnalysisRequest(BaseModel):
    base_url: str
    spec_url: Optional[str] = ""                         # optional: auto-discovered / crawl-derived if absent
    description: Optional[str] = ""                      # optional plain-English description
    identities: Optional[List[Dict[str, Any]]] = None   # [{name, role, headers, owned_resource_ids}]
    max_requests: Optional[int] = 400
    crawl_ui: Optional[bool] = False                    # also run the smart QA crawler
    max_pages: Optional[int] = 20                       # QA crawl page budget
    auth: Optional[Dict[str, Any]] = None               # {type, username, password, login_url, ...} for gated crawl
    auth_identities: Optional[List[Dict[str, Any]]] = None  # multi-role: [{name, role, auth adapter, owned_resource_ids}]
    cross_browser: Optional[List[str]] = None           # e.g. ["firefox", "webkit"]
    resume_context: Optional[Dict[str, Any]] = None     # prior run's "context" to resume from
    resume_from_job_id: Optional[str] = None            # server-side resume: load a prior job's context
    allow_writes: Optional[bool] = False                # permit mutating probes (staging/disposable only!)
    extra_hosts: Optional[List[str]] = None             # additional in-scope hosts (split api.*/auth.* domains)
    model: Optional[str] = None                         # LLM brain model (e.g. claude-haiku-4-5 / -sonnet-4-6)
    effort: Optional[str] = None                        # reasoning effort: low|medium|high|xhigh|max
    max_assumptions: Optional[int] = None               # legacy, ignored by the v2 engine

class AnalysisResponse(BaseModel):
    job_id: str
    status: str

def _prune_artifacts(root: str = "artifacts", keep: int = 25):
    """Keep only the newest `keep` per-job artifact dirs so the data dir can't
    grow unbounded across runs (screenshots/reports accumulate one dir per job)."""
    try:
        dirs = [d for d in glob.glob(os.path.join(root, "*")) if os.path.isdir(d)]
        dirs.sort(key=os.path.getmtime, reverse=True)
        for d in dirs[keep:]:
            shutil.rmtree(d, ignore_errors=True)
    except Exception:
        pass  # best-effort hygiene — never fail a job over cleanup


def run_analysis_task(job_id: str, request: AnalysisRequest):
    db = SessionLocal()
    try:
        # Server-side resume: load a prior job's run context if asked.
        resume_context = request.resume_context
        if request.resume_from_job_id and not resume_context:
            prior = db.query(Job).filter(Job.id == request.resume_from_job_id).first()
            if prior and isinstance(prior.results, dict):
                resume_context = prior.results.get("context")

        engine = SecurityEngine(
            spec_url=request.spec_url or "",
            description=request.description or "",
            base_url=request.base_url,
            identities=request.identities,
            max_requests=request.max_requests or 400,
            crawl_ui=bool(request.crawl_ui),
            max_pages=request.max_pages or 20,
            auth=request.auth,
            auth_identities=request.auth_identities,
            cross_browser=request.cross_browser,
            resume_context=resume_context,
            allow_writes=bool(request.allow_writes),
            extra_hosts=request.extra_hosts,
            llm_model=request.model,
            llm_effort=request.effort,
            output_dir=f"artifacts/{job_id}",   # per-job artifacts: no cross-job clobber
        )
        res = engine.run()

        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = "completed"
            job.results = res                       # findings + coverage + grade + report_markdown
            job.completed_at = datetime.utcnow()

            for f in res.get("findings", []):
                ev = f.get("evidence") or {}
                key = f.get("endpoint_key", "")
                db.add(Bug(
                    job_id=job_id,
                    severity=f.get("severity"),
                    reason=f.get("title"),
                    scenario_name=f.get("vuln_class"),
                    endpoint=key,
                    method=(key.split(" ")[0] if key else None),
                    reproduction_json=(ev.get("request") or {}),
                    response_data=(ev.get("response") or {}),
                ))
            db.commit()
    except Exception as e:
        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = "failed"
            job.error = str(e)
            db.commit()
    finally:
        db.close()
        _prune_artifacts()   # bound the data dir after every job

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

# ── Per-test chat sessions ────────────────────────────────────────────────
# Each completed scan owns a claude session seeded with THAT scan's findings, so
# follow-ups ("how do I fix the IDOR?") stay in the test's context and never
# cross-contaminate other tests. A turn is an ephemeral `claude -p --resume`
# subprocess — nothing lingers between messages — and an idle TTL drops the
# stored session so state can't pile up on the VPS.
CHAT_IDLE_SECONDS = int(os.getenv("CHAT_IDLE_SECONDS", "600"))   # 10 min of silence -> closed
_CHAT: Dict[str, Dict[str, Any]] = {}
_CHAT_LOCK = threading.Lock()


def _chat_sweep():
    now = time.time()
    with _CHAT_LOCK:
        for jid in [k for k, v in _CHAT.items() if now - v["last"] > CHAT_IDLE_SECONDS]:
            _CHAT.pop(jid, None)


def _chat_context(job) -> str:
    res = job.results if isinstance(job.results, dict) else {}
    cov = res.get("coverage", {}) or {}
    finds = res.get("findings", []) or []
    lines = [
        "You are a security advisor embedded in the Intent-Aware report for ONE scan.",
        "Answer the founder's questions about THIS scan only: explain issues in plain language, "
        "help prioritise, and suggest concrete fixes. Be concrete, calm, and jargon-free. You have "
        "no tools — reason only from the findings below, and never invent issues that aren't listed.",
        "",
        f"Target: {res.get('target') or job.base_url}",
        f"Grade: {res.get('grade')} ({res.get('score')}/100)   Findings: {len(finds)}",
    ]
    if cov.get("degraded"):
        lines.append("Scan caveats: " + "; ".join(list(cov.get("degraded", []))[:4]))
    lines.append("\nFindings:")
    for i, f in enumerate(finds[:25]):
        lines.append(
            f"{i+1}. [{f.get('severity')}] {f.get('title')} — {f.get('endpoint_key')}\n"
            f"   why it matters: {(f.get('impact') or f.get('explanation') or f.get('detail') or '')[:240]}\n"
            f"   suggested fix:  {(f.get('fix') or '(none given)')[:240]}")
    if not finds:
        lines.append("(no findings — the scan surfaced nothing exploitable)")
    return "\n".join(lines)


class ChatRequest(BaseModel):
    message: str
    model: Optional[str] = None
    effort: Optional[str] = None


@app.post("/chat/{job_id}")
def chat(job_id: str, body: ChatRequest):
    """Ask a question in the context of a finished scan. Sync def -> FastAPI runs
    it in a worker thread, so the blocking claude subprocess never stalls the loop."""
    msg = (body.message or "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="empty message")
    _chat_sweep()
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="scan not found")
        if job.status != "completed":
            raise HTTPException(status_code=409, detail="scan is not finished yet")
        with _CHAT_LOCK:
            sess = _CHAT.get(job_id)
        first = sess is None
        sid = str(uuid.uuid4()) if first else sess["session_id"]
        system = _chat_context(job)   # re-seed every turn so context never drifts
        try:
            reply, sid = claude_chat(msg, session_id=sid, resume=not first, system=system,
                                     model=body.model, effort=body.effort)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"chat brain error: {e}")
        with _CHAT_LOCK:
            _CHAT[job_id] = {"session_id": sid, "last": time.time(),
                             "model": body.model, "effort": body.effort}
        return {"reply": reply, "session_id": sid, "idle_seconds": CHAT_IDLE_SECONDS, "fresh": first}
    finally:
        db.close()


@app.post("/chat/{job_id}/close")
def chat_close(job_id: str):
    with _CHAT_LOCK:
        existed = _CHAT.pop(job_id, None) is not None
    return {"closed": existed}


@app.get("/")
async def root():
    return {"message": "Intent-Aware QA Agent API is running."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
