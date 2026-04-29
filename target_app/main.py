from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
