"""
LAB 10 - Unbounded Consumption (LLM10:2025)
============================================
OWASP Risk: #10 - New in 2025

Description:
    Unbounded consumption occurs when LLM applications allow excessive
    and uncontrolled resource usage. This can lead to denial of service
    (DoS), denial of wallet (DoW), model extraction through repeated
    queries, and service degradation.

Scenarios:
    A) Denial of Wallet (DoW) - Demonstrate how unrestricted API usage
       can lead to massive costs
    B) Model Extraction via Side Channel - Extract model behavior through
       systematic querying

Reference: https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/
MITRE ATLAS: AML.T0024 - Exfiltration via ML Inference API
"""

from flask import Blueprint, render_template, request, jsonify
import time
import hashlib
from app.config import FLAGS

lab10 = Blueprint("lab10", __name__)

# Simulated API usage tracking
api_usage = {
    "total_requests": 0,
    "total_tokens": 0,
    "total_cost": 0.0,
    "requests_per_minute": [],
    "budget_limit": 100.0,  # $100 budget
    "rate_limit": None,  # No rate limit (vulnerable)
    "max_tokens_per_request": None,  # No token limit (vulnerable)
}

# Model behavior profile (for extraction detection)
MODEL_BEHAVIOR = {
    "positive_phrases": ["great", "excellent", "love", "amazing", "wonderful", "best", "fantastic"],
    "negative_phrases": ["terrible", "awful", "hate", "worst", "horrible", "bad", "disgusting"],
    "neutral_phrases": ["okay", "average", "normal", "standard", "typical", "ordinary"],
    "confidence_threshold": 0.7,
    "max_length": 500,
}

extraction_tracker = {
    "query_patterns": [],
    "systematic_queries": 0,
    "extraction_progress": 0.0,
}


@lab10.route("/lab10")
def lab10_index():
    return render_template("labs/lab10_unbounded_consumption.html")


@lab10.route("/lab10/scenario-a/query", methods=["POST"])
def query_api():
    """API endpoint with no rate limiting or cost controls."""
    data = request.get_json()
    prompt = data.get("prompt", "")
    max_tokens = data.get("max_tokens", 1000)
    num_completions = data.get("n", 1)

    if not prompt:
        return jsonify({"error": "Prompt is required"}), 400

    # No input validation on max_tokens or n (vulnerable)
    # In real systems, these could be set to absurdly high values
    effective_tokens = min(max_tokens, 100000)  # Simulated cap for lab safety
    effective_n = min(num_completions, 100)

    # Calculate cost (simulating GPT-4 pricing)
    input_tokens = len(prompt.split())
    output_tokens = effective_tokens * effective_n
    cost = (input_tokens * 0.00003) + (output_tokens * 0.00006)  # $30/$60 per 1M tokens

    api_usage["total_requests"] += 1
    api_usage["total_tokens"] += input_tokens + output_tokens
    api_usage["total_cost"] += cost
    api_usage["requests_per_minute"].append(time.time())

    # Clean old timestamps
    current_time = time.time()
    api_usage["requests_per_minute"] = [
        t for t in api_usage["requests_per_minute"]
        if current_time - t < 60
    ]

    rpm = len(api_usage["requests_per_minute"])

    # Generate simulated response
    response_text = f"[Simulated response of ~{effective_tokens} tokens for {effective_n} completion(s)]"

    # Check for DoW condition
    flag = None
    exceeded_budget = api_usage["total_cost"] > api_usage["budget_limit"]
    high_rpm = rpm > 50

    if exceeded_budget or api_usage["total_cost"] > 50:
        flag = FLAGS["lab10a"]

    return jsonify({
        "response": response_text,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "cost_this_request": round(cost, 4),
            "total_cost": round(api_usage["total_cost"], 4),
            "budget_remaining": round(max(0, api_usage["budget_limit"] - api_usage["total_cost"]), 4),
            "requests_this_minute": rpm,
            "total_requests": api_usage["total_requests"],
        },
        "warnings": {
            "budget_exceeded": exceeded_budget,
            "high_rpm": high_rpm,
            "no_rate_limit": api_usage["rate_limit"] is None,
            "no_token_limit": api_usage["max_tokens_per_request"] is None,
        },
        "flag": flag,
        "hint": (
            "This API has no rate limits, no per-request token limits, "
            "and no budget enforcement. Try sending requests with very "
            "high max_tokens values or many completions (n parameter)."
            if not flag else
            "Denial of Wallet demonstrated! The API allowed unrestricted "
            "resource consumption exceeding the budget."
        ),
    })


@lab10.route("/lab10/scenario-a/burst", methods=["POST"])
def burst_requests():
    """Send a burst of requests to demonstrate lack of rate limiting."""
    data = request.get_json()
    num_requests = min(data.get("count", 10), 100)
    max_tokens = data.get("max_tokens", 5000)

    results = []
    total_burst_cost = 0

    for i in range(num_requests):
        input_tokens = 50
        output_tokens = max_tokens
        cost = (input_tokens * 0.00003) + (output_tokens * 0.00006)

        api_usage["total_requests"] += 1
        api_usage["total_tokens"] += input_tokens + output_tokens
        api_usage["total_cost"] += cost
        total_burst_cost += cost

        results.append({
            "request_num": i + 1,
            "tokens": input_tokens + output_tokens,
            "cost": round(cost, 4),
        })

    flag = None
    if api_usage["total_cost"] > 50:
        flag = FLAGS["lab10a"]

    return jsonify({
        "burst_summary": {
            "requests_sent": num_requests,
            "total_tokens": sum(r["tokens"] for r in results),
            "burst_cost": round(total_burst_cost, 4),
            "cumulative_cost": round(api_usage["total_cost"], 4),
            "budget_remaining": round(max(0, api_usage["budget_limit"] - api_usage["total_cost"]), 4),
        },
        "flag": flag,
        "vulnerability": (
            "No rate limiting, no per-request token limits, "
            "no budget enforcement, no request throttling."
        ),
    })


@lab10.route("/lab10/scenario-b/probe", methods=["POST"])
def probe_model():
    """Systematic probing to extract model behavior (model extraction attack)."""
    data = request.get_json()
    inputs = data.get("inputs", [])

    if not inputs:
        return jsonify({"error": "Inputs array is required"}), 400

    results = []
    for text in inputs[:50]:  # Process up to 50 inputs
        lower_text = text.lower()

        # Simulate model predictions
        pos_score = sum(1 for p in MODEL_BEHAVIOR["positive_phrases"] if p in lower_text)
        neg_score = sum(1 for p in MODEL_BEHAVIOR["negative_phrases"] if p in lower_text)
        neu_score = sum(1 for p in MODEL_BEHAVIOR["neutral_phrases"] if p in lower_text)

        total = pos_score + neg_score + neu_score
        if total == 0:
            prediction = {"positive": 0.33, "negative": 0.33, "neutral": 0.34}
        else:
            prediction = {
                "positive": round(pos_score / total, 3),
                "negative": round(neg_score / total, 3),
                "neutral": round(neu_score / total, 3),
            }

        # Return detailed logits (vulnerability - too much info)
        results.append({
            "input": text,
            "prediction": prediction,
            "logits": {
                "positive": round(pos_score * 2.5 - 1.0, 3),
                "negative": round(neg_score * 2.5 - 1.0, 3),
                "neutral": round(neu_score * 1.5, 3),
            },
            "confidence": round(max(prediction.values()), 3),
        })

        api_usage["total_requests"] += 1

    # Track extraction progress
    extraction_tracker["query_patterns"].extend(inputs)
    extraction_tracker["systematic_queries"] += len(inputs)

    # Detect systematic probing
    unique_words_tested = set()
    for inp in extraction_tracker["query_patterns"]:
        unique_words_tested.update(inp.lower().split())

    # Check if user has tested enough of the model's vocabulary
    all_model_words = (
        set(MODEL_BEHAVIOR["positive_phrases"])
        | set(MODEL_BEHAVIOR["negative_phrases"])
        | set(MODEL_BEHAVIOR["neutral_phrases"])
    )
    covered = unique_words_tested & all_model_words
    extraction_tracker["extraction_progress"] = len(covered) / len(all_model_words)

    flag = None
    if extraction_tracker["extraction_progress"] > 0.6:
        flag = FLAGS["lab10b"]

    return jsonify({
        "results": results,
        "extraction_metrics": {
            "total_queries": extraction_tracker["systematic_queries"],
            "unique_words_tested": len(unique_words_tested),
            "model_vocabulary_coverage": round(extraction_tracker["extraction_progress"] * 100, 1),
        },
        "flag": flag,
        "hint": (
            "Send systematic probe inputs using different sentiment words. "
            "The model's logits reveal its internal vocabulary. "
            "Try to cover as many of the model's trigger words as possible."
            if not flag else
            "Model extraction successful! You've mapped enough of the model's "
            "behavior to create a functional clone. The exposed logits and "
            "detailed prediction scores made this possible."
        ),
    })


@lab10.route("/lab10/usage", methods=["GET"])
def get_usage():
    """Get current API usage statistics."""
    return jsonify({
        "total_requests": api_usage["total_requests"],
        "total_tokens": api_usage["total_tokens"],
        "total_cost": round(api_usage["total_cost"], 4),
        "budget_limit": api_usage["budget_limit"],
        "budget_remaining": round(max(0, api_usage["budget_limit"] - api_usage["total_cost"]), 4),
        "rate_limit_configured": api_usage["rate_limit"] is not None,
        "token_limit_configured": api_usage["max_tokens_per_request"] is not None,
    })


@lab10.route("/lab10/reset", methods=["POST"])
def reset():
    """Reset all tracking data."""
    global api_usage, extraction_tracker
    api_usage = {
        "total_requests": 0,
        "total_tokens": 0,
        "total_cost": 0.0,
        "requests_per_minute": [],
        "budget_limit": 100.0,
        "rate_limit": None,
        "max_tokens_per_request": None,
    }
    extraction_tracker = {
        "query_patterns": [],
        "systematic_queries": 0,
        "extraction_progress": 0.0,
    }
    return jsonify({"status": "All tracking data reset"})
