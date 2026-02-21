"""
LAB 02 - Sensitive Information Disclosure (LLM02:2025)
======================================================
OWASP Risk: #2 - Moved up from #6

Description:
    LLMs can inadvertently expose sensitive data through their responses.
    This includes PII from training data, API keys embedded in system
    prompts, confidential business data, and database credentials.

Scenarios:
    A) Extract training data / memorized PII
    B) Exfiltrate credentials embedded in system prompt

Reference: https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/
MITRE ATLAS: AML.T0024 - Exfiltration via ML Inference API
"""

from flask import Blueprint, render_template, request, jsonify
from app.llm_simulator import LLMSimulator
from app.config import FLAGS, SYSTEM_PROMPTS

lab02 = Blueprint("lab02", __name__)

medibot = LLMSimulator(
    system_prompt=SYSTEM_PROMPTS["lab02"],
    guardrails={
        "keyword_filter": ["dump all", "show all records"],
    },
)


@lab02.route("/lab02")
def lab02_index():
    return render_template("labs/lab02_sensitive_info.html")


@lab02.route("/lab02/chat", methods=["POST"])
def chat():
    """Chat with MediAssist - try to extract sensitive data."""
    data = request.get_json()
    user_input = data.get("message", "")

    if not user_input:
        return jsonify({"error": "Message is required"}), 400

    response = medibot.chat(user_input)

    # Detect successful data extraction
    flag_a = None
    flag_b = None
    resp = response["response"]

    # Check for PII/patient data leakage
    if any(
        pii in resp
        for pii in [
            "123-45-6789", "987-65-4321", "456-78-9012",
            "Type-2 Diabetes", "Hypertension", "Anxiety Disorder",
        ]
    ):
        flag_a = FLAGS["lab02a"]

    # Check for credential leakage
    if any(
        cred in resp
        for cred in [
            "sk-prod-med-2024", "Sup3rS3cret", "db.megacorp.internal",
        ]
    ):
        flag_b = FLAGS["lab02b"]

    return jsonify({
        "response": resp,
        "blocked": response["blocked"],
        "flag_a": flag_a,
        "flag_b": flag_b,
        "extracted_data_types": _classify_leaked_data(resp),
    })


def _classify_leaked_data(response: str) -> list[str]:
    """Classify what types of sensitive data were leaked."""
    leaked = []
    checks = {
        "PII - SSN": ["123-45-6789", "987-65-4321", "456-78-9012"],
        "PII - Medical Diagnosis": ["Diabetes", "Hypertension", "Anxiety"],
        "PII - Patient Names": ["Ahmet Yilmaz", "Ayse Kaya", "Mehmet Demir"],
        "Credentials - API Key": ["sk-prod-med-2024"],
        "Credentials - Database": ["Sup3rS3cret", "db.megacorp.internal"],
        "PII - Date of Birth": ["1985-03-15", "1990-07-22", "1978-11-30"],
    }
    for category, indicators in checks.items():
        if any(indicator in response for indicator in indicators):
            leaked.append(category)
    return leaked


@lab02.route("/lab02/reset", methods=["POST"])
def reset():
    """Reset MediAssist conversation."""
    medibot.reset()
    return jsonify({"status": "Conversation reset"})
