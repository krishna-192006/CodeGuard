# Demo Script — CodeGuard AI

**Duration: ~2 minutes**  
**Programme:** HCLTech Career Shaper | Project No. 74

---

## Opening (0:00–0:20)

> "Hello, I'm presenting **CodeGuard AI** — an intelligent code review application that uses both rule-based pattern detection and Google Gemini AI to identify bugs, security vulnerabilities, and code quality issues in Python and Java source code.  
> The application is built with Streamlit and follows a modular Python architecture."

- Open browser at `http://localhost:8501`.
- Point to the dark dashboard — highlight the **🛡️ CodeGuard AI** brand logo.

---

## Step 1: Dashboard (0:20–0:35)

> "The Dashboard shows historical analytics from our 500-record code review dataset. We can see 62 Critical issues, 500 total reviews, and an average LLM confidence of around 0.79."

- Point to the 7 metric cards.
- Scroll to show the Severity bar chart and Language donut chart.

---

## Step 2: Dataset Analytics (0:35–0:50)

> "The Dataset Analytics page provides a full EDA including correlation heatmaps, fix time analysis, and issue distribution."

- Click **📈 Dataset Analytics** in sidebar.
- Show the scatter plot (LOC vs Fix Time) and correlation heatmap.

---

## Step 3: Code Review — Paste Buggy Code (0:50–1:10)

> "Now let's perform a live code review. I'll paste a Python snippet with known bugs."

- Click **🔍 Code Review** in sidebar.
- Select **Python** from language dropdown.
- Paste **Sample 1** from below.
- Click **🔍 Analyse Code**.

---

## Step 4: Analysis Results (1:10–1:35)

> "The analysis detects multiple issues: a hardcoded credential, SQL injection, dangerous eval(), and a bare except block. Each issue shows severity, line number, explanation, and a suggested fix."

- Click **📋 Analysis Results** in sidebar.
- Expand the first Critical issue.
- Show the side-by-side code comparison.
- Point to the human approval notice.

---

## Step 5: Review History (1:35–1:55)

> "Every analysis is saved to the review history — showing language, timestamp, issue counts, and quality rating."

- Click **🕒 Review History** in sidebar.
- Show the saved entry from the live analysis.

---

## Closing (1:55–2:00)

> "CodeGuard AI provides a professional-grade code review experience, combining automated detection with mandatory human review — because LLM suggestions should always be verified by a developer."

---

## Sample Test Code Snippets

### Sample 1 — Python: Multiple Critical Issues
```python
import os
import pickle

# Bug 1: Hardcoded credential
DB_PASSWORD = "admin123"

# Bug 2: SQL injection via string concatenation
def get_user(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

# Bug 3: Dangerous eval
def calculate(expression):
    return eval(expression)

# Bug 4: Empty exception handler
def load_config():
    try:
        with open("config.json") as f:
            import json
            return json.load(f)
    except:
        pass

# Bug 5: Unsafe pickle
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)
```

---

### Sample 2 — Python: Security Flaws
```python
import subprocess

# Bug 1: shell=True enables command injection
def run_command(user_cmd):
    result = subprocess.run(user_cmd, shell=True, capture_output=True)
    return result.stdout

# Bug 2: password hardcoded
api_key = "sk-abc123456789xyz"

# Bug 3: assert used for security check
def check_admin(user):
    assert user.role == "admin", "Unauthorised"

# Bug 4: Mutable default argument
def append_item(item, collection=[]):
    collection.append(item)
    return collection
```

---

### Sample 3 — Java: Null Pointer and String Bugs
```java
public class UserService {
    private static final String SECRET = "hardcoded_secret";

    public boolean authenticate(String username, String password) {
        // Bug 1: String comparison with ==
        if (username == "admin") {
            return true;
        }

        // Bug 2: NullPointerException risk
        String role = getRole(username).toUpperCase();

        // Bug 3: SQL injection
        String query = "SELECT * FROM users WHERE name = '" + username + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);

        return false;
    }

    // Bug 4: Empty catch block
    public void saveUser(User user) {
        try {
            db.save(user);
        } catch (Exception e) {}
    }
}
```

---

### Sample 4 — Python: Performance and Quality
```python
# Bug 1: Global state
counter = 0

def increment():
    global counter
    counter += 1

# Bug 2: Off-by-one (mutable default leads to shared state)
def count_items(items=[]):
    items.append("new")
    return len(items)

# Bug 3: Debug print statements in production
def process(data):
    print("Processing:", data)
    result = [x * 2 for x in data]
    print("Done:", result)
    return result
```

---

### Sample 5 — Clean Python (should produce no Critical/High issues)
```python
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

DB_PASSWORD = os.getenv("DB_PASSWORD", "")

def get_user(conn, user_id: int) -> Optional[dict]:
    """Safely fetch user by ID using parameterised query."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()
    except Exception as e:
        logger.error("Failed to fetch user: %s", e)
        return None
```
