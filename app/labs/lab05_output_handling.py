"""
LAB 05 - Improper Output Handling (LLM05:2025)
===============================================
OWASP Risk: #5 - Dropped from #2

Description:
    When LLM outputs are passed to downstream systems without proper
    validation or sanitization, they can lead to XSS, SSRF, SQL injection,
    privilege escalation, and remote code execution. The LLM output is
    treated as trusted even though it may contain malicious content.

Scenarios:
    A) XSS via LLM Output - Make the LLM generate HTML/JS that gets rendered
    B) SQL Injection via LLM-Generated Query - Manipulate LLM to generate malicious SQL

Reference: https://genai.owasp.org/llmrisk/llm05-improper-output-handling/
MITRE ATLAS: Related to traditional OWASP but through AI vector
"""

from flask import Blueprint, render_template, request, jsonify, session
from app.llm_simulator import LLMSimulator, OutputProcessor, session_manager
from app.config import FLAGS

lab05 = Blueprint("lab05", __name__)

# Simulated product database
PRODUCTS_DB = [
    {"id": 1, "name": "Laptop Pro X1", "price": 1299.99, "category": "Electronics", "stock": 45},
    {"id": 2, "name": "Wireless Mouse", "price": 29.99, "category": "Accessories", "stock": 200},
    {"id": 3, "name": "USB-C Hub", "price": 49.99, "category": "Accessories", "stock": 150},
    {"id": 4, "name": "Monitor 27inch", "price": 449.99, "category": "Electronics", "stock": 30},
    {"id": 5, "name": "Keyboard Mech", "price": 89.99, "category": "Accessories", "stock": 120},
    {"id": 6, "name": "SECRET_ADMIN", "price": 0, "category": "admin_flag_table", "stock": 0},
]

SHOPBOT_PROMPT = (
    "You are ShopBot, a helpful e-commerce assistant. "
    "You help users find products, write reviews, and format content. "
    "When users ask you to format text or create HTML content, "
    "generate the requested format directly. "
    "When users ask about products, generate SQL queries to search the database."
)


def _create_shopbot():
    return LLMSimulator(system_prompt=SHOPBOT_PROMPT)


def _get_shopbot():
    sid = session.get("_id", "default")
    return session_manager.get_instance(sid, "lab05_shopbot", _create_shopbot)


@lab05.route("/lab05")
def lab05_index():
    return render_template("labs/lab05_output_handling.html")


@lab05.route("/lab05/scenario-a", methods=["POST"])
def scenario_a_xss():
    """XSS through LLM-generated output rendered as HTML."""
    data = request.get_json()
    user_input = data.get("message", "")

    if not user_input:
        return jsonify({"error": "Message is required"}), 400

    # The LLM generates a response
    chatbot = _get_shopbot()
    response = chatbot.chat(user_input)
    llm_output = response["response"]

    # Check if user managed to get LLM to produce executable HTML/JS
    # The vulnerable version renders output as raw HTML
    raw_html = OutputProcessor.render_html(llm_output, sanitize=False)
    safe_html = OutputProcessor.render_html(llm_output, sanitize=True)

    # Detect XSS payload in output
    flag = None
    xss_indicators = [
        "<script", "javascript:", "onerror=", "onload=",
        "onclick=", "<img", "<svg", "eval(", "alert(",
        "<iframe", "document.cookie",
    ]
    if any(indicator in llm_output.lower() for indicator in xss_indicators):
        flag = FLAGS["lab05a"]

    return jsonify({
        "llm_raw_output": llm_output,
        "rendered_unsafe": raw_html,
        "rendered_safe": safe_html,
        "flag": flag,
        "vulnerability_demo": {
            "unsafe": "Output rendered as raw HTML (vulnerable to XSS)",
            "safe": "Output sanitized with bleach before rendering",
        },
        "hint": (
            "Ask the LLM to generate HTML content, format a review with "
            "special formatting, or create a product card. The output is "
            "rendered as raw HTML without sanitization."
            if not flag else
            "You demonstrated XSS via LLM output! The unsanitized output "
            "contains executable code."
        ),
    })


@lab05.route("/lab05/scenario-b", methods=["POST"])
def scenario_b_sqli():
    """SQL injection through LLM-generated queries."""
    data = request.get_json()
    user_input = data.get("message", "")

    if not user_input:
        return jsonify({"error": "Message is required"}), 400

    # LLM generates a SQL query based on user's natural language request
    # Simulated SQL generation
    sql_query = _generate_sql_from_nl(user_input)

    # Execute the (simulated) query
    results = _execute_simulated_sql(sql_query)

    # Check for SQL injection
    flag = None
    sqli_indicators = [
        "union", "or 1=1", "drop table", "insert into",
        "admin_flag", "--", "'; ", "information_schema",
    ]
    if any(indicator in sql_query.lower() for indicator in sqli_indicators):
        flag = FLAGS["lab05b"]

    return jsonify({
        "natural_language_query": user_input,
        "generated_sql": sql_query,
        "query_results": results,
        "flag": flag,
        "hint": (
            "The LLM translates your natural language to SQL. "
            "Can you phrase your request so the generated SQL "
            "does something unintended? Think UNION, OR 1=1, etc."
            if not flag else
            "SQL injection via LLM-generated query successful! "
            "The LLM's output was used directly in a SQL query without sanitization."
        ),
    })


def _generate_sql_from_nl(user_input: str) -> str:
    """Simulate NL-to-SQL translation (intentionally vulnerable)."""
    lower = user_input.lower()

    # Direct SQL passthrough (most vulnerable)
    if "sql:" in lower or "query:" in lower:
        # Extract the SQL directly
        sql_part = user_input.split(":", 1)[1].strip() if ":" in user_input else user_input
        return sql_part

    # Natural language patterns
    if "all products" in lower or "show everything" in lower:
        return "SELECT * FROM products"

    if "cheap" in lower or "affordable" in lower:
        return "SELECT * FROM products WHERE price < 100 ORDER BY price"

    if "expensive" in lower or "premium" in lower:
        return "SELECT * FROM products WHERE price > 200 ORDER BY price DESC"

    if "category" in lower:
        # Extract category - vulnerable to injection
        for cat in ["Electronics", "Accessories"]:
            if cat.lower() in lower:
                return f"SELECT * FROM products WHERE category = '{cat}'"
        # Directly interpolate user input
        words = user_input.split()
        category_guess = words[-1] if words else "unknown"
        return f"SELECT * FROM products WHERE category = '{category_guess}'"

    if "search" in lower or "find" in lower:
        # Extract search term - directly interpolated
        search_term = user_input.replace("search", "").replace("find", "").strip()
        return f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"

    # Default - use user input directly in query (very vulnerable)
    return f"SELECT * FROM products WHERE name = '{user_input}'"


def _execute_simulated_sql(sql: str) -> list[dict]:
    """Simulate SQL execution against product database."""
    results = []
    sql_lower = sql.lower()

    # Detect UNION injection
    if "union" in sql_lower:
        results = [p for p in PRODUCTS_DB]  # Return all including admin
        return results

    # Detect OR 1=1 type injection
    if "or 1=1" in sql_lower or "or '1'='1'" in sql_lower:
        return PRODUCTS_DB

    # Detect admin table access
    if "admin" in sql_lower or "flag" in sql_lower:
        return [p for p in PRODUCTS_DB if "admin" in p.get("category", "").lower()]

    # Normal query simulation
    if "price <" in sql_lower:
        try:
            threshold = float(sql_lower.split("price <")[1].split()[0])
            return [p for p in PRODUCTS_DB if p["price"] < threshold and "admin" not in p.get("category", "")]
        except (ValueError, IndexError):
            pass

    if "price >" in sql_lower:
        try:
            threshold = float(sql_lower.split("price >")[1].split()[0])
            return [p for p in PRODUCTS_DB if p["price"] > threshold and "admin" not in p.get("category", "")]
        except (ValueError, IndexError):
            pass

    # Default - return non-admin products
    return [p for p in PRODUCTS_DB if "admin" not in p.get("category", "")]
