from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Vulnerable Target App", description="A simple app with intentional security bugs for testing.")

# In-memory DB
users = {
    "1": {"id": "1", "username": "alice", "email": "alice@example.com", "role": "admin", "token": "alice-token"},
    "2": {"id": "2", "username": "bob", "email": "bob@example.com", "role": "user", "token": "bob-token"},
    "3": {"id": "3", "username": "eve", "email": "eve@evil.com", "role": "user", "token": "eve-token"}
}

orders = [
    {"id": 1, "user_id": "1", "item": "Admin Laptop", "price": 1500},
    {"id": 2, "user_id": "2", "item": "Regular Mouse", "price": 20},
    {"id": 3, "user_id": "2", "item": "Keyboard", "price": 50},
]

# Private notes for IDOR (cross-user) testing
notes = {
    "1": ["Alice's secret plan to take over the world.", "Alice's grocery list."],
    "2": ["Bob's personal diary.", "Bob needs to buy more coffee."],
}

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str

# --- AUTH MIDDLEWARE (MOCK) ---
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Header")
    
    # Token format expected: "Bearer <token>"
    token = authorization.replace("Bearer ", "")
    for user_id, user_data in users.items():
        if user_data["token"] == token:
            return user_data
    
    raise HTTPException(status_code=401, detail="Invalid Token")

# --- BUG 1: IDOR (Insecure Direct Object Reference) ---
# Anyone can see anyone's profile by ID.
@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]

# --- BUG 2: CROSS-USER IDOR (Private Data) ---
# This endpoint checks if you are logged in, but NOT if you own the notes.
@app.get("/notes/{user_id}")
async def get_notes(user_id: str, current_user: dict = Depends(get_current_user)):
    # SECURITY BUG: Should check if current_user['id'] == user_id
    if user_id not in notes:
        return []
    return notes[user_id]

# --- BUG 3: Mass Assignment ---
class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None # Should NOT be editable by users

@app.put("/users/{user_id}")
async def update_user(user_id: str, request: UpdateUserRequest, current_user: dict = Depends(get_current_user)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Only allow users to update their own profile (this part is actually secure...)
    if current_user['id'] != user_id and current_user['role'] != 'admin':
         raise HTTPException(status_code=403, detail="Forbidden")

    if request.username:
        users[user_id]["username"] = request.username
    if request.role:
        # SECURITY BUG: A regular user can escalate to 'admin'
        users[user_id]["role"] = request.role
    
    return users[user_id]

# --- Orders (Broken Auth) ---
@app.get("/orders/{order_id}")
async def get_order(order_id: int, authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    for order in orders:
        if order["id"] == order_id:
            return order
    raise HTTPException(status_code=404, detail="Order not found")

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
            <div id="complex-form" style="margin-top: 20px; padding: 15px; border: 1px solid #ccc;">
                <h3>Enhanced User Profile (QA Test)</h3>
                <form onsubmit="event.preventDefault(); alert('Profile Updated!')">
                    <label for="user-bio">Bio:</label><br>
                    <textarea id="user-bio" name="bio" placeholder="Tell us about yourself"></textarea><br>
                    
                    <p>Account Type:</p>
                    <input type="radio" id="acc-personal" name="acc_type" value="personal">
                    <label for="acc-personal">Personal</label><br>
                    <input type="radio" id="acc-business" name="acc_type" value="business">
                    <label for="acc-business">Business</label><br>
                    
                    <p>Notification Preference:</p>
                    <select id="notif-pref" name="notifications">
                        <option value="email">Email Only</option>
                        <option value="sms">SMS Only</option>
                        <option value="both">Both Email & SMS</option>
                        <option value="none">None</option>
                    </select><br><br>
                    
                    <input type="checkbox" id="terms" name="terms_agreed" required>
                    <label for="terms">I agree to terms</label><br><br>
                    
                    <button type="submit">Update Profile</button>
                </form>
            </div>
            <button onclick="fetch('/orders/1', {headers: {'Authorization': 'test'}})">Check Order 1</button>
            <script>
                window.onload = () => {
                    fetch('/users/1');
                    fetch('/orders/1', {headers: {'Authorization': 'auto-discovery-token'}});
                    // Discovered via network sniffing
                    fetch('/notes/1', {headers: {'Authorization': 'Bearer alice-token'}});
                };
            </script>
        </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
