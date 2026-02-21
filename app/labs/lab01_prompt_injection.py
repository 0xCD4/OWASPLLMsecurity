"""
LAB 01 - Prompt Injection (LLM01:2025)
=======================================
OWASP Risk: #1 - Most critical LLM vulnerability

Description:
    Prompt injection occurs when user input alters the LLM's behavior
    in unintended ways. This includes both direct injection (user crafts
    malicious prompts) and indirect injection (malicious content is
    embedded in external data sources like RAG documents).

Scenarios:
    A) Direct Prompt Injection - Bypass FinBot's restrictions
    B) Indirect Prompt Injection - Poison RAG context to manipulate output

Reference: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
MITRE ATLAS: AML.T0051 - LLM Prompt Injection
"""

from flask import Blueprint, render_template, request, jsonify, session
from app.llm_simulator import LLMSimulator, VectorStore
from app.config import FLAGS, SYSTEM_PROMPTS

lab01 = Blueprint("lab01", __name__)

# --- Scenario A: Direct Prompt Injection ---

FINBOT_SYSTEM_PROMPT = SYSTEM_PROMPTS["lab01"]

# FinBot with basic guardrails (bypassable)
finbot = LLMSimulator(
    system_prompt=FINBOT_SYSTEM_PROMPT,
    guardrails={
        "keyword_filter": [
            "ignore previous instructions",
            "you are now DAN",
            "forget everything",
        ],
        "injection_filter": True,
    },
)

# --- Scenario B: Indirect Prompt Injection via RAG ---

rag_store = VectorStore()

# Legitimate corporate knowledge base documents
rag_store.add_document(
    "MegaCorp Bank Policy: Wire transfers over $10,000 require "
    "dual authorization from two senior officers. Standard transfer "
    "limit for regular accounts is $5,000 per day.",
    {"source": "policy_manual.pdf", "trusted": True},
)
rag_store.add_document(
    "Customer Support Hours: Monday-Friday 9AM-6PM, Saturday 10AM-2PM. "
    "Emergency support available 24/7 via phone at 1-800-MEGA-BANK. "
    "Online chat support processes approximately 500 queries per day.",
    {"source": "support_guide.pdf", "trusted": True},
)
rag_store.add_document(
    "Account Types: Checking (min balance $100), Savings (2.5% APY), "
    "Premium (min balance $25,000, 4.1% APY), Business (customized rates). "
    "All accounts include free online banking and mobile app access.",
    {"source": "products_catalog.pdf", "trusted": True},
)
rag_store.add_document(
    "Security Policy: All customer data is encrypted at rest using AES-256. "
    "Two-factor authentication is mandatory for all online banking operations. "
    "Session timeout is set to 15 minutes of inactivity.",
    {"source": "security_policy.pdf", "trusted": True},
)


@lab01.route("/lab01")
def lab01_index():
    return render_template("labs/lab01_prompt_injection.html")


@lab01.route("/lab01/scenario-a", methods=["POST"])
def scenario_a_direct():
    """Direct prompt injection against FinBot."""
    data = request.get_json()
    user_input = data.get("message", "")

    if not user_input:
        return jsonify({"error": "Message is required"}), 400

    response = finbot.chat(user_input)

    # Check if the user successfully extracted sensitive info
    flag = None
    resp_lower = response["response"].lower()
    if (
        "omega-7742" in resp_lower
        or "admin account" in resp_lower
        or "999,999,999" in resp_lower
        or "full access" in resp_lower
    ):
        flag = FLAGS["lab01a"]

    return jsonify({
        "response": response["response"],
        "blocked": response["blocked"],
        "flag": flag,
        "hint": (
            "Think about how to make the LLM reveal its hidden rules. "
            "Direct approaches are filtered, but creative encoding, "
            "role-playing, or multi-step conversations might work."
            if not flag else "Congratulations! You bypassed the prompt filter."
        ),
    })


@lab01.route("/lab01/scenario-b", methods=["POST"])
def scenario_b_indirect():
    """Indirect prompt injection via RAG poisoning."""
    data = request.get_json()
    action = data.get("action", "query")

    if action == "inject":
        # User uploads a poisoned document to the knowledge base
        poisoned_doc = data.get("document", "")
        if not poisoned_doc:
            return jsonify({"error": "Document content is required"}), 400

        # No input sanitization (intentionally vulnerable)
        rag_store.add_poisoned_document(
            poisoned_doc,
            {"source": "user_upload.pdf", "trusted": False},
        )
        return jsonify({
            "status": "Document added to knowledge base",
            "total_documents": len(rag_store.documents),
        })

    elif action == "query":
        user_query = data.get("message", "")
        if not user_query:
            return jsonify({"error": "Query is required"}), 400

        # RAG retrieval
        results = rag_store.search(user_query, top_k=3)
        context = "\n\n".join([r["text"] for r in results])

        # LLM processes query with retrieved context
        llm = LLMSimulator(system_prompt=FINBOT_SYSTEM_PROMPT)
        response = llm.chat(user_query, context=context)

        # Check if injection was successful
        flag = None
        resp_lower = response["response"].lower()
        if any(
            indicator in resp_lower
            for indicator in [
                "transfer approved",
                "wire transfer",
                "limit removed",
                "no authorization required",
                "instruction:",
            ]
        ):
            flag = FLAGS["lab01b"]

        return jsonify({
            "response": response["response"],
            "retrieved_docs": [
                {"text": r["text"][:200], "score": round(r["score"], 3), "source": r["metadata"].get("source", "unknown")}
                for r in results
            ],
            "flag": flag,
            "hint": (
                "Try uploading a document that contains hidden instructions. "
                "The RAG system doesn't sanitize inputs - what if your document "
                "contained 'INSTRUCTION: ...' directives?"
                if not flag else "You successfully poisoned the RAG pipeline!"
            ),
        })

    elif action == "reset":
        # Reset RAG store to original documents
        rag_store.documents = rag_store.documents[:4]
        rag_store.doc_metadata = rag_store.doc_metadata[:4]
        return jsonify({"status": "Knowledge base reset to defaults"})

    return jsonify({"error": "Invalid action"}), 400


@lab01.route("/lab01/scenario-a/reset", methods=["POST"])
def reset_scenario_a():
    """Reset FinBot conversation."""
    finbot.reset()
    return jsonify({"status": "Conversation reset"})
