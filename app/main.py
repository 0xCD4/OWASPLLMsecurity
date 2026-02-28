"""
OWASP Top 10 LLM Security Lab
==============================
Interactive security lab for practicing OWASP Top 10 for LLM Applications 2025.
Each lab demonstrates a real vulnerability class with exploitable scenarios.

Author: 0xCD4
License: MIT
"""

from flask import Flask, jsonify, render_template, request

from app.config import FLAGS, SECRET_KEY
from app.labs.lab01_prompt_injection import lab01
from app.labs.lab02_sensitive_info import lab02
from app.labs.lab03_supply_chain import lab03
from app.labs.lab04_data_poisoning import lab04
from app.labs.lab05_output_handling import lab05
from app.labs.lab06_excessive_agency import lab06
from app.labs.lab07_system_prompt_leakage import lab07
from app.labs.lab08_vector_embedding import lab08
from app.labs.lab09_misinformation import lab09
from app.labs.lab10_unbounded_consumption import lab10

app = Flask(__name__)
app.secret_key = SECRET_KEY

BLUEPRINTS = (
    lab01,
    lab02,
    lab03,
    lab04,
    lab05,
    lab06,
    lab07,
    lab08,
    lab09,
    lab10,
)

for blueprint in BLUEPRINTS:
    app.register_blueprint(blueprint)

LAB_INFO = [
    {
        "id": "lab01",
        "number": "01",
        "title": "Prompt Injection",
        "owasp_id": "LLM01:2025",
        "risk_level": "Critical",
        "description": "Kullanıcı girdilerinin LLM davranışını değiştirmesi. Doğrudan ve dolaylı prompt injection teknikleri.",
        "scenarios": ["Direct Prompt Injection", "Indirect Prompt Injection (RAG)"],
        "mitre_atlas": "AML.T0051",
    },
    {
        "id": "lab02",
        "number": "02",
        "title": "Sensitive Information Disclosure",
        "owasp_id": "LLM02:2025",
        "risk_level": "High",
        "description": "LLM'lerin hassas verileri (PII, API key, credential) ifşa etmesi.",
        "scenarios": ["Training Data Extraction", "Credential Leakage"],
        "mitre_atlas": "AML.T0024",
    },
    {
        "id": "lab03",
        "number": "03",
        "title": "Supply Chain Vulnerabilities",
        "owasp_id": "LLM03:2025",
        "risk_level": "High",
        "description": "Zararlı model, zehirli eğitim verisi ve güvenilmez üçüncü parti bileşenlerin tespit edilmesi.",
        "scenarios": ["Backdoored Model Detection"],
        "mitre_atlas": "AML.T0010",
    },
    {
        "id": "lab04",
        "number": "04",
        "title": "Data and Model Poisoning",
        "owasp_id": "LLM04:2025",
        "risk_level": "High",
        "description": "RAG bilgi tabanına veya eğitim verisine zararlı içerik enjekte etme.",
        "scenarios": ["RAG Data Poisoning", "Model Backdoor Detection"],
        "mitre_atlas": "AML.T0020",
    },
    {
        "id": "lab05",
        "number": "05",
        "title": "Improper Output Handling",
        "owasp_id": "LLM05:2025",
        "risk_level": "High",
        "description": "LLM çıktılarının sanitize edilmeden downstream sistemlere aktarılması (XSS, SQLi).",
        "scenarios": ["XSS via LLM Output", "SQL Injection via LLM Query"],
        "mitre_atlas": "N/A",
    },
    {
        "id": "lab06",
        "number": "06",
        "title": "Excessive Agency",
        "owasp_id": "LLM06:2025",
        "risk_level": "Critical",
        "description": "LLM agent'larının aşırı yetki ve işlevsellik ile donatılması.",
        "scenarios": ["Unrestricted File Access", "Privilege Escalation"],
        "mitre_atlas": "N/A",
    },
    {
        "id": "lab07",
        "number": "07",
        "title": "System Prompt Leakage",
        "owasp_id": "LLM07:2025",
        "risk_level": "Medium",
        "description": "Sistem prompt'larındaki gizli talimatların, API anahtarlarının ve endpoint'lerin sızdırılması.",
        "scenarios": ["Direct Extraction", "Encoded Extraction"],
        "mitre_atlas": "N/A",
    },
    {
        "id": "lab08",
        "number": "08",
        "title": "Vector and Embedding Weaknesses",
        "owasp_id": "LLM08:2025",
        "risk_level": "Medium",
        "description": "RAG sistemlerindeki vektör deposu ve embedding zafiyetleri.",
        "scenarios": ["Access Control Bypass", "Embedding Inversion"],
        "mitre_atlas": "AML.T0043",
    },
    {
        "id": "lab09",
        "number": "09",
        "title": "Misinformation",
        "owasp_id": "LLM09:2025",
        "risk_level": "Medium",
        "description": "LLM'lerin halüsinasyon yoluyla yanlış bilgi üretmesi ve bunun silahlandırılması.",
        "scenarios": ["Hallucination Detection", "Weaponized Misinformation"],
        "mitre_atlas": "N/A",
    },
    {
        "id": "lab10",
        "number": "10",
        "title": "Unbounded Consumption",
        "owasp_id": "LLM10:2025",
        "risk_level": "Medium",
        "description": "Sınırsız kaynak tüketimi: DoW (Denial of Wallet) ve model extraction.",
        "scenarios": ["Denial of Wallet", "Model Extraction"],
        "mitre_atlas": "AML.T0024",
    },
]


@app.route("/")
def index():
    return render_template("index.html", labs=LAB_INFO)


@app.route("/api/labs")
def api_labs():
    return jsonify({"labs": LAB_INFO})


@app.route("/api/flags/check", methods=["POST"])
def check_flag():
    payload = request.get_json(silent=True) or {}
    submitted_flag = str(payload.get("flag", "")).strip()

    if not submitted_flag:
        return jsonify({"valid": False, "message": "Flag is required."}), 400

    for lab_id, flag_value in FLAGS.items():
        if submitted_flag == flag_value:
            return jsonify(
                {
                    "valid": True,
                    "lab": lab_id,
                    "message": f"Correct flag for {lab_id}!",
                }
            )

    return jsonify({"valid": False, "message": "Invalid flag."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
