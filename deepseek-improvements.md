# Complete Improvement Guide for Intent-Aware QA Agent

## What Your Agent SHOULD Be Able To Handle

Based on your project vision, here's what the agent must master:

### Core Capabilities Target
1. **Full API Discovery** — Not just what's on the page, but EVERY endpoint from OpenAPI spec
2. **Multi-Context Testing** — Test from different user perspectives (admin, user, anonymous, attacker)
3. **Contract Violation Detection** — "This should fail with 403 but got 200" = BUG
4. **State-Aware Attacks** — Understand "first login, then access, then compare results"
5. **Semantic Bug Detection** — "Response is valid JSON but contains wrong user's data"

---

## IMPROVEMENT AREA 1: Hybrid API Discovery

### Current Problem
Your crawler only finds endpoints visible in the HTML page (3 endpoints). The OpenAPI spec at `/openapi.json` has ALL endpoints but the agent isn't reading it properly.

### What to Implement

**Rule: Always merge two discovery sources**
```
Priority 1: OpenAPI/Swagger Spec (complete endpoint catalog)
Priority 2: Shadow Spec from crawler (real-world usage patterns)
```

**Required behaviors:**
1. When visiting any page, actively fetch `/openapi.json`, `/swagger.json`, `/docs`
2. Parse the OpenAPI spec to extract ALL paths, methods, parameters, and schemas
3. Merge with crawler findings — spec endpoints get tested even if crawler didn't see them
4. Flag mismatches: "Endpoint in spec but not found in UI" = potential hidden/undocumented endpoint

**What this changes:**
- Your agent would have found `PUT /users/{id}` (the mass assignment bug endpoint)
- Would have found `GET /orders/{id}` with its auth header requirement
- Would have tested ALL methods: GET, POST, PUT, DELETE, PATCH

---

## IMPROVEMENT AREA 2: User Context Model

### Current Problem
The agent makes all requests as a single anonymous session. It doesn't simulate different user roles.

### What to Implement

**Rule: Create distinct user personas for every test**
```
Personas:
1. Anonymous (no auth)
2. Authenticated User (alice/bob with valid token)
3. Admin User (alice with admin privileges)
4. Attacker (bob trying to access alice's data)
5. Invalid Auth (fake/expired token)
```

**Required structure for each persona:**
```json
{
  "persona_id": "user_bob",
  "role": "user",
  "auth_type": "bearer_token",
  "credentials": {"token": "valid_user_token"},
  "resources_owned": ["user_id:2", "orders:[2,3]"],
  "permissions": ["read_own_profile", "read_own_orders"]
}
```

**Required behaviors:**
1. For EVERY endpoint, run the same test from multiple personas
2. Compare results: "Anonymous gets 200 on /users/1" = BUG (should be 401)
3. "Bob gets 200 on /orders/1" = BUG (that's Alice's order)
4. Track "resource ownership" — each persona knows what data should be theirs
5. Cross-persona access attempts: Bob tries to access Alice's resources

---

## IMPROVEMENT AREA 3: Contract-Based Adversarial Generation

### Current Problem
The agent generated weak tests (PUT to /users/-1) instead of truly adversarial tests targeting assumptions.

### What to Implement

**Rule: Every assumption generates concrete violation attempts**

**Assumption categories and their test patterns:**

#### A. Authorization Assumptions
```
Assumption: "Only authenticated users can access resources"
Test Patterns:
- Request without auth header → expect 401
- Request with invalid auth → expect 401
- Request with expired token → expect 401
- Request with another user's token → expect 403

Assumption: "Users can only see their own data"
Test Patterns:
- User A requests User B's resource → expect 403
- User A requests list endpoint → response must NOT contain User B's items
- Modify resource ID in URL to another user's → expect 403
```

#### B. Data Integrity Assumptions
```
Assumption: "Order total must equal sum of items"
Test Pattern:
- Create order, calculate expected total, compare with response
- Modify items after order placed → total should update or reject

Assumption: "Email must be unique"
Test Pattern:
- Register with existing email → expect 409
- Update profile to use another user's email → expect 409
```

#### C. Role/Permission Assumptions
```
Assumption: "Only admins can modify user roles"
Test Patterns:
- Regular user tries to update own role → expect 403
- Regular user tries to update another user's role → expect 403
- Test all fields in update request for mass assignment
```

#### D. Business Logic Assumptions
```
Assumption: "Cart checkout requires items in cart"
Test Pattern:
- Checkout with empty cart → expect 400
- Checkout with negative quantities → expect 400
- Checkout after removing all items but before cart refresh → expect 400

Assumption: "Price cannot be negative"
Test Pattern:
- Create product with negative price → expect 422
- Update product to negative price → expect 422
```

---

## IMPROVEMENT AREA 4: Stateful Test Sequences

### Current Problem
Tests are single requests. Real bugs require sequences.

### What to Implement

**Rule: Generate multi-step attack scenarios**

**Required sequence types:**

```
1. Login → Access Protected → Compare Results
   Step 1: Authenticate as Bob
   Step 2: Request Alice's profile
   Step 3: Assert 403 or Alice's data not in response

2. Create → Read → Verify Ownership
   Step 1: Alice creates a resource
   Step 2: Bob tries to read that resource
   Step 3: Assert Bob gets 403 or resource not visible

3. Update → Verify Side Effects
   Step 1: Bob updates his profile (trying to set role=admin)
   Step 2: Bob reads his profile
   Step 3: Assert role is NOT admin (or request was rejected)

4. Register → Login → Access
   Step 1: Register new user
   Step 2: Login as new user
   Step 3: Try to access admin endpoints
   Step 4: Assert all admin endpoints return 403
```

---

## IMPROVEMENT AREA 5: Semantic Bug Detection Rules

### Current Problem
The agent only catches HTTP errors, not "wrong but successful" responses.

### What to Implement

**Rule: Define what "wrong" looks like for every endpoint**

**Detection patterns by bug type:**

#### IDOR Detection
```
Pattern: Cross-User Data Access
Check: Request user ID ≠ Response data owner ID
Example: Bob requests /users/1 → Gets Alice's data → BUG
Detection: Compare requested user_id with response.user_id (or similar field)
Severity: CRITICAL
```

#### Broken Authentication Detection
```
Pattern: Auth Bypass
Check: Request requires auth per spec, but succeeds with no/invalid auth
Example: Spec says "Authorization header required" → Send without → 200 OK → BUG
Detection: Compare actual status with expected status from spec
Severity: CRITICAL
```

#### Mass Assignment Detection
```
Pattern: Privilege Fields Modified
Check: Non-admin successfully changes restricted fields
Example: Bob sends {"role": "admin"} in update → role changes → BUG
Detection: Send update with elevated privilege fields → Read back → compare
Severity: CRITICAL
```

#### Data Leakage Detection
```
Pattern: Sensitive Data in Response
Check: Response contains fields not in spec or unexpected data
Example: User list returns password hashes, tokens, or internal IDs
Detection: Compare response schema with spec schema
Severity: HIGH
```

#### Business Logic Detection
```
Pattern: Invalid State Transitions
Check: Action succeeds when it shouldn't based on current state
Example: Checkout succeeds with empty cart, or negative balance
Detection: Track state → assert preconditions → verify postconditions
Severity: HIGH
```

---

## IMPROVEMENT AREA 6: Enhanced Failure Classification

### Current Problem
Bug #4 was labeled "validation error" when it was actually a mass assignment vulnerability.

### What to Implement

**Rule: Classify bugs by security impact, not by HTTP status**

**Required classification system:**
```
CRITICAL:
- Authentication bypass (access without credentials)
- Authorization bypass (access others' data)
- Privilege escalation (user becomes admin)
- Data breach (sensitive data exposed)

HIGH:
- IDOR on sensitive resources
- Mass assignment of privilege fields
- Business logic bypass (checkout without payment)

MEDIUM:
- Information disclosure (stack traces, versions)
- Missing rate limiting
- Insecure defaults

LOW:
- Missing security headers
- Verbose error messages
- Debug endpoints exposed
```

**Required: Bug explanation includes**
```
1. What was expected (from spec/contract)
2. What actually happened (actual response)
3. Why it's a security issue (impact)
4. Attack scenario (how an attacker would exploit)
5. Affected data/users
```

---

## IMPROVEMENT AREA 7: Smarter Input Generation

### Current Problem
The form filler used generic "test" values everywhere.

### What to Implement

**Rule: Generate context-aware malicious inputs**

**Input categories:**

```
1. Boundary Values
   - Empty strings, null, undefined
   - Maximum/minimum integers
   - Strings at max length
   - Special characters: < > ' " ; ` / \
   - Unicode/special chars: emoji, RTL override
   
2. Type Confusion
   - String where number expected
   - Array where object expected
   - Boolean where string expected
   - JSON injection: {"$gt": ""}
   
3. ID Manipulation
   - Sequential IDs: /users/1, /users/2, /users/3
   - Negative IDs: /users/-1
   - Zero: /users/0
   - Very large IDs: /users/999999
   - Non-numeric: /users/admin, /users/*
   
4. Auth Token Variations
   - Empty token
   - "Bearer null"
   - "Bearer undefined"
   - Expired JWT
   - Another user's token
   - Admin token used by non-admin
   
5. Mass Assignment Fields
   - role: "admin"
   - isAdmin: true
   - permissions: ["*"]
   - isVerified: true
   - credit: 999999
   - discount: 100
```

---

## IMPROVEMENT AREA 8: Coverage Tracking

### Current Problem
No visibility into what's been tested and what hasn't.

### What to Implement

**Required coverage dimensions:**
```
1. Endpoint Coverage: Which endpoints tested?
   - Track: method + path combinations
   - Goal: 100% of discovered endpoints

2. Method Coverage: Which HTTP methods per endpoint?
   - Track: GET, POST, PUT, DELETE, PATCH, OPTIONS
   - Goal: All methods in spec, plus OPTIONS for discovery

3. Persona Coverage: Which user types tested each endpoint?
   - Track: endpoint × persona matrix
   - Goal: Every endpoint tested by every persona

4. Parameter Coverage: Which parameters tested?
   - Track: Path params, query params, headers, body fields
   - Goal: All parameters tested with valid + malicious values

5. Status Code Coverage: Which response codes received?
   - Track: 200, 201, 400, 401, 403, 404, 422, 500
   - Goal: Test conditions that SHOULD trigger each status
```

---

## IMPROVEMENT AREA 9: The Agent Loop Decision Priority

### What to Implement

**Priority queue for the agent loop:**
```
1. CRITICAL: Auth/Authz tests (IDOR, privilege escalation)
   → Most impactful bugs
   → Test first, every endpoint, every persona
   
2. HIGH: Data integrity tests (mass assignment, data leakage)
   → Requires understanding response schema
   → Test after we know what "correct" looks like
   
3. MEDIUM: Input validation (injection, boundary values)
   → Catches DoS, crashes, error disclosure
   → Run after auth tests (many endpoints won't be reachable)
   
4. LOW: Business logic sequences
   → Multi-step scenarios
   → Run last, requires state tracking
```

**Loop decision rules:**
```
IF endpoint not tested by any persona:
    → Priority: IMMEDIATE
    
IF endpoint tested but only by admin:
    → Priority: HIGH (test as regular user)
    
IF auth test passed (should have failed):
    → Priority: CRITICAL (escalate)
    → Explore what else this broken auth unlocks
    
IF new endpoint discovered during exploration:
    → Priority: HIGH (add to queue immediately)
```

---

## IMPROVEMENT AREA 10: Report Quality

### What to Implement

**Required report improvements:**

```
1. Executive Summary
   - Critical bugs found (with one-line impact)
   - Overall security posture (A-F grade)
   - Time to fix estimate

2. Bug Grouping
   - Group related bugs (e.g., "IDOR affects 5 endpoints")
   - Show pattern: "Authorization missing on all /users/* endpoints"

3. Reproduction Steps
   - Step-by-step with exact requests
   - Include authentication context
   - curl commands for easy verification

4. Impact Analysis
   - What data is exposed
   - How many users affected
   - Compliance implications (GDPR, PCI, etc.)

5. Fix Suggestions
   - Not just "what's wrong" but "how to fix"
   - Code examples for common patterns
```

---

## SUMMARY: What Your Agent Must Handle After Improvements

| Bug Type | Detection Method | Test Pattern | Priority |
|---|---|---|---|
| IDOR | Cross-persona response comparison | Bob accesses Alice's resource | CRITICAL |
| Broken Auth | Missing/invalid auth test | Request without token | CRITICAL |
| Mass Assignment | Privilege field modification | Non-admin sets role=admin | CRITICAL |
| Data Leakage | Response schema comparison | Unexpected fields in response | HIGH |
| Business Logic | State transition validation | Invalid sequence succeeds | HIGH |
| Input Validation | Boundary/malicious input | Negative IDs, injections | MEDIUM |
| Rate Limiting | Concurrent requests | Rapid fire requests | MEDIUM |
| Info Disclosure | Error message analysis | Stack traces, versions | LOW |
| Broken UI Links | Crawl status codes | 404 on linked pages | LOW |
| JS Errors | Console monitoring | Client-side exceptions | LOW |
