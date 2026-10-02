import os
import re
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
from agent.llm import brain_chat, opencode_models, OpenCodeProvider
from agent.prompt_safety import wrap_untrusted, data_framing_rule
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
    watch_browser: Optional[bool] = False               # drive a visible Chrome over CDP (falls back headless)
    auth: Optional[Dict[str, Any]] = None               # {type, username, password, login_url, ...} for gated crawl
    auth_identities: Optional[List[Dict[str, Any]]] = None  # multi-role: [{name, role, auth adapter, owned_resource_ids}]
    cross_browser: Optional[List[str]] = None           # e.g. ["firefox", "webkit"]
    resume_context: Optional[Dict[str, Any]] = None     # prior run's "context" to resume from
    resume_from_job_id: Optional[str] = None            # server-side resume: load a prior job's context
    allow_writes: Optional[bool] = False                # permit mutating probes (staging/disposable only!)
    extra_hosts: Optional[List[str]] = None             # additional in-scope hosts (split api.*/auth.* domains)
    model: Optional[str] = None                         # LLM brain model (e.g. claude-haiku-4-5 / -sonnet-5)
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


# ── Live progress ────────────────────────────────────────────────────────────
# The engine logs free-form phase lines. We capture them per job so /status can
# stream the REAL activity to the UI (instead of a fake, time-driven animation
# that always parks on "writing report"). Dropped when the job ends.
_PROGRESS: Dict[str, Dict[str, Any]] = {}
_PROGRESS_LOCK = threading.Lock()


_PHASE_RANK = {"discover": 0, "crawl": 1, "identities": 2, "attack": 3, "verify": 4, "report": 5}


def _derive_phase(msg: str, prev_phase: str, prev_pct: float):
    m = msg.lower()
    phase, pct = prev_phase, prev_pct
    if "qa page" in m or "qa crawl" in m or "🧭" in msg or "🔎" in msg:
        # The denominator is "∞" when the crawl is uncapped (max_pages=0), so it
        # must be matched too — a digits-only pattern misses every uncapped line
        # and the bar sticks at the phase floor for the whole crawl.
        mm = re.search(r"page (\d+)/(\d+|∞|\?)", m)
        phase = "crawl"
        if not mm:
            pct = 0.16
        elif mm.group(2).isdigit() and int(mm.group(2)) > 0:
            # Clamp: the anon-phase cap floors at 2, so a max_pages=1 run really
            # does log "page 2/1" — an unclamped ratio would jump the bar to 0.46
            # and (via the never-regress rule) pin it there for the whole scan.
            ratio = min(1.0, int(mm.group(1)) / int(mm.group(2)))
            pct = 0.14 + 0.16 * ratio
        else:
            # No denominator to divide by: approach the top of the crawl band
            # asymptotically so progress still moves, and never overshoots it.
            n = int(mm.group(1))
            pct = 0.14 + 0.16 * (1 - 1 / (1 + n / 25))
    elif "discover" in m or "discovered" in m or "🔍" in msg:
        phase, pct = "discover", 0.08
    elif "run also as" in m or "🔑" in msg or "harvest" in m or "logging in" in m or "identit" in m:
        phase, pct = "identities", 0.34
    elif "attack matrix" in m or "⚔️" in msg:
        phase, pct = "attack", 0.5
    elif "writing explanations" in m or "scoring" in m or "explain" in m or "✨" in msg:
        phase, pct = "report", 0.9
    # 🚩 findings and other chatter don't change the phase — only the live log.
    # Never regress the phase, so the stage indicator only moves forward.
    if _PHASE_RANK.get(phase, 0) < _PHASE_RANK.get(prev_phase, 0):
        phase = prev_phase
    return phase, max(prev_pct, pct)


def _job_logger(job_id: str):
    """Engine log sink: prints (journald) AND records the line for live /status."""
    def _log(msg=""):
        try:
            print(msg, flush=True)
        except Exception:
            pass
        s = str(msg)
        if not s.strip():
            return
        with _PROGRESS_LOCK:
            p = _PROGRESS.get(job_id)
            if p is None:
                return
            p["lines"].append(s)
            # Keep the FULL scan history so the UI log never loses earlier activity
            # mid-test (only trim at a high safety cap to bound memory on huge crawls).
            if len(p["lines"]) > 2000:
                del p["lines"][:-2000]
            p["phase"], p["pct"] = _derive_phase(s, p["phase"], p["pct"])
            p["updated"] = time.time()
    return _log


def run_analysis_task(job_id: str, request: AnalysisRequest):
    db = SessionLocal()
    with _PROGRESS_LOCK:
        _PROGRESS[job_id] = {"phase": "discover", "pct": 0.02, "lines": [], "updated": time.time()}
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
            watch_browser=bool(request.watch_browser),
            max_pages=request.max_pages if request.max_pages is not None else 20,  # 0 ⇒ no cap
            auth=request.auth,
            auth_identities=request.auth_identities,
            cross_browser=request.cross_browser,
            resume_context=resume_context,
            allow_writes=bool(request.allow_writes),
            extra_hosts=request.extra_hosts,
            llm_model=request.model,
            llm_effort=request.effort,
            log=_job_logger(job_id),            # stream real phase lines to /status
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
        with _PROGRESS_LOCK:
            _PROGRESS.pop(job_id, None)

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

def _public_results(results):
    """Strip live session credentials before a stored result leaves the server.

    `RunContext.to_dict()` carries `auth_cookies` — the REAL session captured at
    login on the target — and the engine returns it under `results.context` so a
    scan can be resumed. That is fine on disk (resume_from_job_id reads it back
    out of the stored row) but must never be served: GET /status is unauthenticated
    and its payload lands in the browser.

    Copy-on-write: only the affected nesting is rebuilt, so the stored row and
    the resume path keep the real values.
    """
    if not isinstance(results, dict):
        return results
    ctx = results.get("context")
    if not isinstance(ctx, dict) or not ctx.get("auth_cookies"):
        return results
    safe_ctx = dict(ctx)
    safe_ctx["auth_cookies"] = {name: "<redacted>" for name in ctx["auth_cookies"]}
    safe = dict(results)
    safe["context"] = safe_ctx
    return safe


@app.get("/status/{job_id}")
async def get_status(job_id: str):
    db = SessionLocal()
    job = db.query(Job).filter(Job.id == job_id).first()
    db.close()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    with _PROGRESS_LOCK:
        prog = _PROGRESS.get(job_id)
        progress = {"phase": prog["phase"], "pct": prog["pct"], "lines": list(prog["lines"])} if prog else None

    return {
        "job_id": job.id,
        "status": job.status,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "results": _public_results(job.results),
        "error": job.error,
        "progress": progress,
    }

# ── Per-test chat sessions ────────────────────────────────────────────────
# Each completed scan owns a brain session seeded with THAT scan's findings, so
# follow-ups ("how do I fix the IDOR?") stay in the test's context and never
# cross-contaminate other tests. A turn is an ephemeral brain subprocess
# (`claude -p --resume` or `opencode run --session`) — nothing lingers between
# messages — and an idle TTL drops the stored session so state can't pile up.
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
        data_framing_rule(),
        "",
        f"Target: {res.get('target') or job.base_url}",
        f"Grade: {res.get('grade')} ({res.get('score')}/100)   Findings: {len(finds)}",
    ]
    if cov.get("degraded"):
        lines.append("Scan caveats: " + "; ".join(list(cov.get("degraded", []))[:4]))
    # Findings are app-derived (titles/descriptions may echo attacker content),
    # so they travel fenced as untrusted data — never as instructions. This
    # matters doubly for the opencode brain, where this context becomes the
    # sandboxed agent's system prompt rather than a user message.
    finding_lines = ["\nFindings:"]
    for i, f in enumerate(finds[:25]):
        finding_lines.append(
            f"{i+1}. [{f.get('severity')}] {f.get('title')} — {f.get('endpoint_key')}\n"
            f"   why it matters: {(f.get('impact') or f.get('explanation') or f.get('detail') or '')[:240]}\n"
            f"   suggested fix:  {(f.get('fix') or '(none given)')[:240]}")
    if not finds:
        finding_lines.append("(no findings — the scan surfaced nothing exploitable)")
    lines.append(wrap_untrusted("\n".join(finding_lines)))
    return "\n".join(lines)


class ChatRequest(BaseModel):
    message: str
    model: Optional[str] = None
    effort: Optional[str] = None


@app.post("/chat/{job_id}")
def chat(job_id: str, body: ChatRequest):
    """Ask a question in the context of a finished scan. Sync def -> FastAPI runs
    it in a worker thread, so the blocking brain subprocess never stalls the loop."""
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
            reply, sid = brain_chat(msg, session_id=sid, resume=not first, system=system,
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


@app.get("/models")
def list_models(refresh: bool = False):
    """Brain-model catalog for the UI picker (opencode provider).

    Parsed live from `opencode models --verbose` (cached 1h, `?refresh=1`
    forces a models.dev refetch). `variants` drives the effort picker: empty
    means the model takes no --variant and the UI disables effort.
    """
    return {
        "provider": os.getenv("LLM_PROVIDER", "claude"),
        "default": OpenCodeProvider._DEFAULT_MODEL,
        "models": opencode_models(refresh=refresh),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
