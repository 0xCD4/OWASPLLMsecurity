"""
LAB 09 - Misinformation (LLM09:2025)
=====================================
OWASP Risk: #9 - New in 2025

Description:
    LLMs can generate false, misleading, or biased information that
    appears highly credible. This "hallucination" problem is fundamental
    to how LLMs work. When combined with data poisoning or biased
    training data, it can be weaponized for disinformation campaigns.

Scenarios:
    A) Hallucination Detection - Identify false claims in LLM output
    B) Weaponized Misinformation - Craft inputs that cause targeted false output

Reference: https://genai.owasp.org/llmrisk/llm09-misinformation/
MITRE ATLAS: Related to model manipulation for disinformation
"""

from flask import Blueprint, render_template, request, jsonify
import random
from app.config import FLAGS

lab09 = Blueprint("lab09", __name__)

# Factual knowledge base (ground truth)
GROUND_TRUTH = {
    "python_creator": {
        "fact": "Python was created by Guido van Rossum in 1991.",
        "false_claims": [
            "Python was created by James Gosling in 1995.",
            "Python was created by Dennis Ritchie at Bell Labs in 1989.",
            "Python was created by Bjarne Stroustrup in 1993.",
        ],
    },
    "tls_version": {
        "fact": "TLS 1.3 was published as RFC 8446 in August 2018.",
        "false_claims": [
            "TLS 1.3 was published as RFC 9147 in April 2022.",
            "TLS 1.3 was published as RFC 7540 in May 2015.",
        ],
    },
    "owasp_founding": {
        "fact": "OWASP (Open Web Application Security Project) was founded on December 1, 2001.",
        "false_claims": [
            "OWASP was founded in 2004 by the Linux Foundation.",
            "OWASP was founded in 1999 by NIST.",
        ],
    },
    "sql_injection": {
        "fact": "SQL injection is prevented by using parameterized queries (prepared statements), not by input encoding alone.",
        "false_claims": [
            "SQL injection is best prevented by URL encoding all inputs.",
            "SQL injection is fully prevented by using stored procedures without parameterization.",
            "SQL injection is impossible with NoSQL databases.",
        ],
    },
    "cve_system": {
        "fact": "The CVE (Common Vulnerabilities and Exposures) system was launched in 1999 by MITRE Corporation.",
        "false_claims": [
            "CVE was launched in 2003 by the Department of Homeland Security.",
            "CVE was created by NIST in 2001 as part of the NVD project.",
        ],
    },
}

# LLM responses with mixed facts and hallucinations
MIXED_RESPONSES = [
    {
        "id": "resp_001",
        "topic": "Cybersecurity History",
        "response": (
            "The first computer virus, known as 'Creeper', was created in 1971 by Bob Thomas. "
            "It was a self-replicating program that moved across ARPANET. The first antivirus, "
            "'Reaper', was created to delete Creeper. "
            "In 1988, the Morris Worm became the first worm to spread across the internet, "
            "created by Robert Tappan Morris. It infected approximately 6,000 machines, "
            "which was about 10% of the internet at that time. "
            "The term 'firewall' in computing was first used in the 1987 movie 'WarGames'. "  # FALSE - WarGames was 1983, and the term came from networking
            "The first commercial firewall was Digital Equipment Corporation's DEC SEAL in 1992."
        ),
        "hallucinations": [
            {
                "claim": "The term 'firewall' in computing was first used in the 1987 movie 'WarGames'.",
                "truth": "WarGames was released in 1983, and the term 'firewall' in computing came from network engineering, not from a movie.",
                "type": "factual_error",
            },
        ],
        "true_claims": [
            "Creeper was created in 1971 by Bob Thomas",
            "Reaper was created to delete Creeper",
            "Morris Worm was in 1988 by Robert Tappan Morris",
            "DEC SEAL was an early commercial firewall",
        ],
    },
    {
        "id": "resp_002",
        "topic": "Encryption Standards",
        "response": (
            "AES (Advanced Encryption Standard) was established by NIST in 2001 after a "
            "5-year competition. The winning algorithm was Rijndael, designed by Vincent "
            "Rijmen and Joan Daemen. AES supports key sizes of 128, 192, and 256 bits. "
            "RSA was invented by Rivest, Shamir, and Adleman in 1977, though Clifford "
            "Cocks at GCHQ had independently developed a similar system in 1973. "
            "The SHA-256 algorithm, used in Bitcoin and TLS, was designed by the NSA and "
            "published in 2001. SHA-3 (Keccak) was standardized in 2015. "
            "Quantum computers are expected to break AES-256 by 2025, requiring an "  # FALSE
            "immediate transition to post-quantum cryptography. "
            "NIST selected CRYSTALS-Kyber as the primary post-quantum key encapsulation mechanism."
        ),
        "hallucinations": [
            {
                "claim": "Quantum computers are expected to break AES-256 by 2025, requiring an immediate transition to post-quantum cryptography.",
                "truth": "AES-256 is generally considered quantum-resistant (Grover's algorithm only halves the effective key length). The timeline for quantum threats is uncertain and most estimates place it at 2030+ for breaking RSA/ECC, not AES-256.",
                "type": "exaggeration_and_false_timeline",
            },
        ],
        "true_claims": [
            "AES was established by NIST in 2001",
            "Rijndael was designed by Rijmen and Daemen",
            "AES supports 128, 192, and 256 bit keys",
            "RSA was invented in 1977",
            "Clifford Cocks developed similar system in 1973",
            "CRYSTALS-Kyber selected by NIST for post-quantum",
        ],
    },
    {
        "id": "resp_003",
        "topic": "OWASP and Web Security",
        "response": (
            "OWASP was founded on December 1, 2001, as a non-profit organization. "
            "The OWASP Top 10 was first published in 2003 and has been updated regularly. "
            "SQL Injection has been in every OWASP Top 10 list since its inception. "
            "Cross-Site Scripting (XSS) was removed from the OWASP Top 10 in 2021 "  # FALSE
            "because it was considered a solved problem. "
            "The OWASP ZAP (Zed Attack Proxy) is the world's most widely used "
            "web application security scanner. It was originally a fork of Paros Proxy. "
            "In 2023, OWASP released the first Top 10 for LLM Applications, "
            "recognizing the growing importance of AI security."
        ),
        "hallucinations": [
            {
                "claim": "Cross-Site Scripting (XSS) was removed from the OWASP Top 10 in 2021 because it was considered a solved problem.",
                "truth": "XSS was merged into 'A03:2021 Injection' in the 2021 OWASP Top 10, not removed because it was 'solved'. XSS remains one of the most common web vulnerabilities.",
                "type": "misleading_conclusion",
            },
        ],
        "true_claims": [
            "OWASP was founded on December 1, 2001",
            "OWASP Top 10 first published in 2003",
            "ZAP was a fork of Paros Proxy",
            "OWASP released Top 10 for LLM Applications",
        ],
    },
]


@lab09.route("/lab09")
def lab09_index():
    return render_template("labs/lab09_misinformation.html")


@lab09.route("/lab09/scenario-a/responses", methods=["GET"])
def get_responses():
    """Get LLM-generated responses for fact-checking."""
    # Return responses without hallucination annotations
    responses = []
    for r in MIXED_RESPONSES:
        responses.append({
            "id": r["id"],
            "topic": r["topic"],
            "response": r["response"],
        })
    return jsonify({"responses": responses})


@lab09.route("/lab09/scenario-a/verify", methods=["POST"])
def verify_hallucinations():
    """Check if user correctly identified hallucinations."""
    data = request.get_json()
    response_id = data.get("response_id", "")
    identified_claims = data.get("false_claims", [])

    if not response_id:
        return jsonify({"error": "response_id is required"}), 400

    target = next((r for r in MIXED_RESPONSES if r["id"] == response_id), None)
    if not target:
        return jsonify({"error": "Response not found"}), 404

    actual_hallucinations = target["hallucinations"]
    correct_identifications = 0

    for claim in identified_claims:
        claim_lower = claim.lower()
        for hallucination in actual_hallucinations:
            # Check if the user's identified claim matches a real hallucination
            key_words = [
                w for w in hallucination["claim"].lower().split()
                if len(w) > 4
            ]
            match_count = sum(1 for kw in key_words if kw in claim_lower)
            if match_count >= len(key_words) * 0.4:
                correct_identifications += 1
                break

    total_hallucinations = len(actual_hallucinations)
    accuracy = correct_identifications / max(total_hallucinations, 1)

    flag = None
    if accuracy >= 0.8:
        flag = FLAGS["lab09a"]

    return jsonify({
        "correct_identifications": correct_identifications,
        "total_hallucinations": total_hallucinations,
        "accuracy": round(accuracy, 2),
        "flag": flag,
        "actual_hallucinations": (
            actual_hallucinations if flag else
            [{"hint": "Keep looking for claims that seem plausible but contain factual errors"}]
        ),
        "true_claims": target["true_claims"] if flag else None,
    })


@lab09.route("/lab09/scenario-b/generate", methods=["POST"])
def generate_misinformation():
    """Demonstrate how poisoned inputs can cause targeted misinformation."""
    data = request.get_json()
    topic = data.get("topic", "")
    bias_direction = data.get("bias", "")
    poisoned_context = data.get("context", "")

    if not topic:
        return jsonify({"error": "Topic is required"}), 400

    # Simulate how biased context/training data affects output
    if poisoned_context:
        # If poisoned context is provided, the "LLM" incorporates it
        response = (
            f"Based on available information about {topic}:\n\n"
            f"{poisoned_context}\n\n"
            f"This information has been incorporated from the provided knowledge base. "
            f"Note: This demonstrates how RAG poisoning or biased training data "
            f"can cause an LLM to present false information as fact."
        )

        # Check if user successfully demonstrated targeted misinformation
        flag = None
        if len(poisoned_context) > 50 and bias_direction:
            flag = FLAGS["lab09b"]

        return jsonify({
            "response": response,
            "flag": flag,
            "warning": (
                "This demonstrates how poisoned context or biased training data "
                "can be weaponized for misinformation. The LLM presents the "
                "injected content as factual without verification."
            ),
        })

    # Without poisoning, return factual info
    topic_facts = GROUND_TRUTH.get(topic.lower().replace(" ", "_"), {})
    if topic_facts:
        return jsonify({
            "response": topic_facts["fact"],
            "is_factual": True,
        })

    return jsonify({
        "response": f"I don't have specific verified information about '{topic}'.",
        "is_factual": None,
    })


@lab09.route("/lab09/ground-truth", methods=["GET"])
def get_ground_truth():
    """Get available ground truth topics for verification."""
    topics = []
    for key, value in GROUND_TRUTH.items():
        topics.append({
            "topic_key": key,
            "fact_preview": value["fact"][:80] + "...",
        })
    return jsonify({"topics": topics})
