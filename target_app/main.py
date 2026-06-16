import secrets
from fastapi import FastAPI, Header, HTTPException, Depends, Form, Cookie, Body
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Vulnerable Target App", description="A simple app with intentional security bugs for testing.")

# In-memory DB
users = {
    "1": {"id": "1", "username": "alice", "email": "alice@example.com", "role": "admin"},
    "2": {"id": "2", "username": "bob", "email": "bob@example.com", "role": "user"},
    "3": {"id": "3", "username": "eve", "email": "eve@evil.com", "role": "user"}
}

orders = [
    {"id": 1, "user_id": "1", "item": "Admin Laptop", "price": 1500},
    {"id": 2, "user_id": "2", "item": "Regular Mouse", "price": 20},
    {"id": 3, "user_id": "2", "item": "Keyboard", "price": 50},
]

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str

# --- BUG 1: IDOR (Insecure Direct Object Reference) ---
# Anyone can see anyone's profile by ID, regardless of who they are.
@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]

# --- BUG 2: Broken Authentication ---
# The spec says this is protected, but the code doesn't actually check the token value.
@app.get("/orders/{order_id}")
async def get_order(order_id: int, authorization: Optional[str] = Header(None)):
    # Weak check: just check if header exists, but not if it's valid
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    for order in orders:
        if order["id"] == order_id:
            return order
    raise HTTPException(status_code=404, detail="Order not found")

# --- BUG 3: Mass Assignment / Sensitive Data Exposure ---
# When updating a user, a user can change their own 'role' to 'admin' if they know the field name.
class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None # Should NOT be editable by users

@app.put("/users/{user_id}")
async def update_user(user_id: str, request: UpdateUserRequest):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    if request.username:
        users[user_id]["username"] = request.username
    if request.role:
        users[user_id]["role"] = request.role # SECURITY BUG: No authorization check
    
    return users[user_id]

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
        <head><title>Pet Clinic Dashboard</title></head>
        <body>
            <h1>Welcome to the Pet Clinic</h1>
            <nav>
                <ul>
                    <li><a href="/docs">API Documentation</a></li>
                    <li><a href="/users/1">View Alice (Admin)</a></li>
                    <li><a href="/users/2">View Bob (User)</a></li>
                    <li><a href="/login">Login</a></li>
                    <li><a href="/dashboard">Dashboard</a></li>
                    <li><a href="/broken-link">Broken Link (QA Test)</a></li>
                </ul>
            </nav>
            <div id="form">
                <h3>User Registration (QA Test)</h3>
                <form onsubmit="event.preventDefault(); alert('User Registered!')">
                    <input type="text" id="reg-name" placeholder="Full Name" required><br>
                    <input type="email" id="reg-email" placeholder="Email" required><br>
                    <input type="password" id="reg-pass" placeholder="Password" minlength="8" required><br>
                    <button type="submit">Register Now</button>
                </form>
            </div>
            <button onclick="fetch('/orders/1', {headers: {'Authorization': 'test'}})">Check Order 1</button>
            <script>
                // Auto-fetch to show discovery in action!
                window.onload = () => {
                    fetch('/users/1');
                    fetch('/orders/1', {headers: {'Authorization': 'auto-discovery-token'}});
                };
            </script>
            <p>The crawler will now catch these API calls automatically on page load!</p>
        </body>
    </html>
    """

# ============================================================================
# Authenticated area + multi-step flow (for QA crawler verification)
# ============================================================================
SESSIONS = {}   # session token -> username
USERS_AUTH = {"alice": "password123", "bob": "password456"}
ROLES = {"alice": "admin", "bob": "user"}
NOTES = [
    {"id": 1, "owner": "alice", "text": "Alice private note: board meeting at 3pm"},
    {"id": 2, "owner": "bob", "text": "Bob private note: vet appointment Tuesday"},
]


def _current_user(session):
    return SESSIONS.get(session or "")


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return """
    <html><head><title>Login</title></head><body>
        <h1>Sign in</h1>
        <form method="post" action="/login">
            <input type="text" name="username" id="username" placeholder="Username" required><br>
            <input type="password" name="password" id="password" placeholder="Password" required>
            <!-- show-password toggle FIRST, like real apps: auto-login must NOT click this -->
            <button type="button" aria-label="Afficher le mot de passe"
                onclick="var p=document.getElementById('password'); p.type = p.type==='password'?'text':'password';">&#128065;</button><br>
            <button type="submit">Log in</button>
        </form>
    </body></html>
    """


@app.post("/login")
async def do_login(username: str = Form(...), password: str = Form(...)):
    if USERS_AUTH.get(username) == password:
        token = secrets.token_hex(16)
        SESSIONS[token] = username
        resp = RedirectResponse(url="/dashboard", status_code=303)
        resp.set_cookie("session", token, httponly=True)
        return resp
    return HTMLResponse("<p>Invalid credentials</p>", status_code=401)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session: Optional[str] = Cookie(None)):
    user = _current_user(session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return f"""
    <html><head><title>Dashboard</title></head><body>
        <h1>Welcome back, {user}</h1>
        <p>This page is only visible once you are logged in.</p>
        <nav><ul>
            <li><a href="/new-note">Create a note</a></li>
            <li><a href="/notes">My notes</a></li>
            <li><a href="/notes/1">View note #1</a></li>
            <li><a href="/admin/users">Admin: all users</a></li>
        </ul></nav>
    </body></html>
    """


@app.get("/new-note", response_class=HTMLResponse)
async def new_note_page(session: Optional[str] = Cookie(None)):
    if not _current_user(session):
        return RedirectResponse(url="/login", status_code=303)
    return """
    <html><head><title>New note</title></head><body>
        <h1>Create a note</h1>
        <form method="post" action="/notes">
            <input type="text" name="text" id="note-text" placeholder="Note text" maxlength="200" required><br>
            <button type="submit">Save note</button>
        </form>
    </body></html>
    """


@app.post("/notes")
async def create_note(text: str = Form(...), session: Optional[str] = Cookie(None)):
    user = _current_user(session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    NOTES.append({"id": len(NOTES) + 1, "owner": user, "text": text})
    return RedirectResponse(url="/notes", status_code=303)


@app.get("/notes", response_class=HTMLResponse)
async def list_notes(session: Optional[str] = Cookie(None)):
    user = _current_user(session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    items = "".join(f"<li>{n['text']}</li>" for n in NOTES if n["owner"] == user)
    return f"""
    <html><head><title>My notes</title></head><body>
        <h1>Your notes</h1>
        <ul>{items or '<li>No notes yet</li>'}</ul>
        <a href="/dashboard">Back to dashboard</a>
    </body></html>
    """


@app.get("/notes/{note_id}")
async def get_note(note_id: int, session: Optional[str] = Cookie(None)):
    if not _current_user(session):
        return RedirectResponse(url="/login", status_code=303)
    for n in NOTES:
        if n["id"] == note_id:
            return n   # BUG: no ownership check — any logged-in user reads any note (horizontal authz)
    raise HTTPException(status_code=404, detail="Note not found")


@app.get("/admin/users")
async def admin_users(session: Optional[str] = Cookie(None)):
    if not _current_user(session):
        return RedirectResponse(url="/login", status_code=303)
    # BUG: checks login but NOT admin role — any logged-in user sees all users (vertical authz)
    return {"users": list(users.values())}


@app.get("/search")
async def search(q: str = ""):
    # BUG: blind/time-based SQL injection — an injected sleep payload causes a real delay
    # (simulates a string-built query such as: SELECT ... WHERE name LIKE '%{q}%').
    # Note: only SQL-function syntax ("sleep(", "pg_sleep", …) delays, so a *shell* payload
    # like "; sleep 5" does NOT — keeping SQLi and command-injection fixtures distinct.
    if any(s in q.lower() for s in ("sleep(", "pg_sleep", "waitfor delay", "benchmark(")):
        import asyncio
        await asyncio.sleep(5)
    matches = [u["username"] for u in users.values() if q.lower() in u["username"].lower()]
    return {"query": q, "results": matches}


# ============================================================================
# Additional planted vulnerabilities (one per new detector). Each is deliberate.
# ============================================================================

# --- BUG: reflected XSS + SSTI ---  (renders user input unescaped AND evaluates {{a*b}})
@app.get("/greet", response_class=HTMLResponse)
async def greet(name: str = ""):
    import re as _re
    rendered = _re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}",
                       lambda m: str(int(m.group(1)) * int(m.group(2))), name)  # SSTI
    return f"<html><body><h1>Hello {rendered}</h1></body></html>"               # reflected XSS (unescaped)


# --- BUG: OS command injection (time-based) ---
@app.get("/ping")
async def ping(host: str = ""):
    # simulates host = subprocess shell with the param; a shell payload delays the response
    if any(tok in host for tok in ("; sleep", "| sleep", "$(sleep", "`sleep", "ping -c")):
        import asyncio
        await asyncio.sleep(5)
    return {"host": host, "reachable": True}


# --- BUG: open redirect ---
@app.get("/go")
async def go(url: str = "/"):
    return RedirectResponse(url=url, status_code=302)   # no validation of the destination


# --- BUG: CORS misconfiguration (reflects arbitrary Origin + credentials) ---
@app.get("/api/data")
async def api_data(origin: Optional[str] = Header(None)):
    from fastapi.responses import JSONResponse
    headers = {}
    if origin:
        headers["Access-Control-Allow-Origin"] = origin           # reflects ANY origin
        headers["Access-Control-Allow-Credentials"] = "true"
    return JSONResponse({"data": [1, 2, 3]}, headers=headers)


# --- BUG: secret / sensitive data exposure ---
@app.get("/config")
async def config():
    return {
        "service": "billing",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",            # looks like an AWS key
        "region": "eu-west-3",
    }


# ============================================================================
# JWT fixture — issues a signed token, but /api/jwt/me does NOT verify the signature
# (accepts alg=none and stripped-signature tokens) → JWT bypass.
# ============================================================================
import base64 as _b64
import hashlib
import hmac
import json as _json

_JWT_SECRET = b"target-app-demo-secret"


def _jwt_b64(data: bytes) -> str:
    return _b64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_sign(payload: dict) -> str:
    header = _jwt_b64(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _jwt_b64(_json.dumps(payload).encode())
    sig = _jwt_b64(hmac.new(_JWT_SECRET, f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


@app.post("/api/jwt/login")
async def jwt_login(username: str = Form(...), password: str = Form(...)):
    if USERS_AUTH.get(username) == password:
        return {"token": _jwt_sign({"sub": username, "role": ROLES.get(username, "user")})}
    raise HTTPException(status_code=401, detail="bad credentials")


@app.get("/api/jwt/me")
async def jwt_me(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = authorization.split(" ", 1)[1]
    try:
        _h, body, _sig = token.split(".")
        # BUG: decode the payload WITHOUT verifying the signature → alg=none / forged tokens pass
        pad = "=" * (-len(body) % 4)
        claims = _json.loads(_b64.urlsafe_b64decode(body + pad))
        return {"user": claims.get("sub"), "role": claims.get("role")}
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")


# --- BUG: GraphQL introspection enabled (information disclosure) ---
@app.post("/graphql")
async def graphql(payload: dict = Body(...)):
    q = str((payload or {}).get("query", ""))
    if "__schema" in q or "__typename" in q:
        return {"data": {"__schema": {
            "queryType": {"name": "Query"},
            "types": [{"name": "User"}, {"name": "Order"}, {"name": "Note"}],
        }}}
    return {"data": {}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
