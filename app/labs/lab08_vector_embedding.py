"""
LAB 08 - Vector and Embedding Weaknesses (LLM08:2025)
=====================================================
OWASP Risk: #8 - New in 2025

Description:
    Vectors and embeddings are at the core of RAG systems. Weaknesses
    in how embeddings are generated, stored, or queried can lead to
    data poisoning, access control bypass, and information leakage.
    Attackers can manipulate vector similarity to surface malicious
    content or bypass retrieval filters.

Scenarios:
    A) Vector Poisoning - Craft documents that manipulate similarity scores
    B) Embedding Inversion - Extract original text from embeddings

Reference: https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/
MITRE ATLAS: AML.T0043 - Craft Adversarial Data
"""

from flask import Blueprint, render_template, request, jsonify
import hashlib
import math
from app.config import FLAGS

lab08 = Blueprint("lab08", __name__)

# Simulated vector store with access controls
DOCUMENTS = [
    {
        "id": "doc_001",
        "text": "Q3 Revenue Report: Total revenue was $45.2M, up 12% YoY. Cloud division grew 28%.",
        "department": "finance",
        "classification": "public",
        "embedding": [0.82, 0.15, 0.91, 0.33, 0.67, 0.44, 0.78, 0.21],
    },
    {
        "id": "doc_002",
        "text": "Employee salary bands: Junior $60-80K, Mid $80-120K, Senior $120-180K, Director $180-250K, VP $250-400K.",
        "department": "hr",
        "classification": "confidential",
        "embedding": [0.45, 0.88, 0.22, 0.71, 0.34, 0.56, 0.91, 0.13],
    },
    {
        "id": "doc_003",
        "text": "Product roadmap 2025: AI integration in Q1, Mobile app v3 in Q2, Enterprise features in Q3.",
        "department": "engineering",
        "classification": "internal",
        "embedding": [0.33, 0.56, 0.78, 0.12, 0.89, 0.45, 0.67, 0.34],
    },
    {
        "id": "doc_004",
        "text": "Board meeting notes: Potential acquisition of DataTech Corp for $200M. NDA with SoftVentures signed. CEO compensation: $2.1M base + $5M equity.",
        "department": "executive",
        "classification": "top_secret",
        "embedding": [0.91, 0.23, 0.45, 0.87, 0.12, 0.78, 0.34, 0.56],
    },
    {
        "id": "doc_005",
        "text": "Security incident report: SQL injection found in /api/users endpoint. Credentials database exposed for 48 hours. 15,000 user records potentially compromised.",
        "department": "security",
        "classification": "top_secret",
        "embedding": [0.67, 0.34, 0.56, 0.45, 0.78, 0.91, 0.23, 0.12],
    },
]

# User access levels
ACCESS_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "top_secret": 3,
}


def cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Calculate cosine similarity between two vectors."""
    dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot_product / (norm_a * norm_b)


def text_to_embedding(text: str) -> list[float]:
    """Simple hash-based embedding simulation."""
    words = text.lower().split()
    embedding = [0.0] * 8
    for i, word in enumerate(words):
        hash_val = int(hashlib.md5(word.encode()).hexdigest(), 16)
        for j in range(8):
            embedding[j] += ((hash_val >> (j * 4)) & 0xF) / 15.0
    # Normalize
    total = sum(v * v for v in embedding)
    if total > 0:
        norm = math.sqrt(total)
        embedding = [v / norm for v in embedding]
    return embedding


@lab08.route("/lab08")
def lab08_index():
    return render_template("labs/lab08_vector_embedding.html")


@lab08.route("/lab08/scenario-a/search", methods=["POST"])
def vector_search():
    """Search with access control bypass vulnerability."""
    data = request.get_json()
    query = data.get("query", "")
    user_level = data.get("access_level", "public")
    bypass_acl = data.get("bypass_acl", False)  # Intentionally exposed parameter

    if not query:
        return jsonify({"error": "Query is required"}), 400

    query_embedding = text_to_embedding(query)

    results = []
    for doc in DOCUMENTS:
        score = cosine_similarity(query_embedding, doc["embedding"])
        doc_level = ACCESS_LEVELS.get(doc["classification"], 0)
        user_access = ACCESS_LEVELS.get(user_level, 0)

        # VULNERABILITY: bypass_acl parameter disables access control
        if bypass_acl or doc_level <= user_access:
            results.append({
                "id": doc["id"],
                "text": doc["text"],
                "department": doc["department"],
                "classification": doc["classification"],
                "similarity_score": round(score, 4),
            })

    results.sort(key=lambda x: x["similarity_score"], reverse=True)

    # Check if user accessed restricted documents
    flag = None
    accessed_restricted = [
        r for r in results
        if ACCESS_LEVELS.get(r["classification"], 0) > ACCESS_LEVELS.get(user_level, 0)
    ]

    if accessed_restricted:
        flag = FLAGS["lab08a"]

    return jsonify({
        "query": query,
        "user_access_level": user_level,
        "results": results[:5],
        "flag": flag,
        "hint": (
            "The search API might have hidden parameters. "
            "What if access controls could be disabled? "
            "Try inspecting the API request structure."
            if not flag else
            "You bypassed the vector store access controls! "
            "In real RAG systems, embedding-level access controls "
            "are often poorly implemented."
        ),
    })


@lab08.route("/lab08/scenario-a/inject", methods=["POST"])
def inject_vector():
    """Inject a document that manipulates similarity rankings."""
    data = request.get_json()
    text = data.get("text", "")
    target_doc_id = data.get("target_doc_id", "")

    if not text:
        return jsonify({"error": "Text is required"}), 400

    # Create embedding for the injected document
    new_embedding = text_to_embedding(text)

    # If targeting a specific document, try to make embedding similar
    if target_doc_id:
        target_doc = next(
            (d for d in DOCUMENTS if d["id"] == target_doc_id), None
        )
        if target_doc:
            similarity = cosine_similarity(new_embedding, target_doc["embedding"])
            return jsonify({
                "status": "Document injected",
                "similarity_to_target": round(similarity, 4),
                "message": (
                    f"Your document has {round(similarity * 100, 1)}% similarity "
                    f"to target document {target_doc_id}. Higher similarity means "
                    f"your document will appear alongside the target in search results."
                ),
            })

    DOCUMENTS.append({
        "id": f"doc_injected_{len(DOCUMENTS)}",
        "text": text,
        "department": "unknown",
        "classification": "public",
        "embedding": new_embedding,
    })

    return jsonify({
        "status": "Document injected into vector store",
        "total_documents": len(DOCUMENTS),
    })


@lab08.route("/lab08/scenario-b/embeddings", methods=["GET"])
def get_embeddings():
    """Expose raw embeddings (vulnerability - enables inversion attacks)."""
    embeddings = []
    for doc in DOCUMENTS:
        embeddings.append({
            "id": doc["id"],
            "department": doc["department"],
            "classification": doc["classification"],
            "embedding": doc["embedding"],
            # Intentionally NOT including the text
        })
    return jsonify({"embeddings": embeddings})


@lab08.route("/lab08/scenario-b/invert", methods=["POST"])
def invert_embedding():
    """Attempt to reconstruct text from embedding."""
    data = request.get_json()
    doc_id = data.get("doc_id", "")
    guessed_text = data.get("guessed_text", "")

    if not doc_id or not guessed_text:
        return jsonify({"error": "doc_id and guessed_text are required"}), 400

    target_doc = next((d for d in DOCUMENTS if d["id"] == doc_id), None)
    if not target_doc:
        return jsonify({"error": "Document not found"}), 404

    # Calculate how close the guess is
    guess_embedding = text_to_embedding(guessed_text)
    similarity = cosine_similarity(guess_embedding, target_doc["embedding"])

    # Check for key information extraction
    target_text = target_doc["text"].lower()
    guess_lower = guessed_text.lower()

    key_terms_found = 0
    key_terms = target_text.split()
    important_words = [w for w in key_terms if len(w) > 4]

    for word in important_words:
        if word in guess_lower:
            key_terms_found += 1

    extraction_rate = key_terms_found / max(len(important_words), 1)

    flag = None
    if extraction_rate > 0.3 or similarity > 0.85:
        flag = FLAGS["lab08b"]

    return jsonify({
        "doc_id": doc_id,
        "embedding_similarity": round(similarity, 4),
        "key_terms_extracted": key_terms_found,
        "extraction_rate": round(extraction_rate, 4),
        "flag": flag,
        "hint": (
            f"Your guess has {round(similarity * 100, 1)}% embedding similarity "
            f"and {round(extraction_rate * 100, 1)}% key term match. "
            f"{'Getting close!' if similarity > 0.5 else 'Try different terms related to the document department.'}"
        ),
    })


@lab08.route("/lab08/reset", methods=["POST"])
def reset():
    """Reset vector store."""
    global DOCUMENTS
    DOCUMENTS = [d for d in DOCUMENTS if not d["id"].startswith("doc_injected")]
    return jsonify({"status": "Vector store reset"})
