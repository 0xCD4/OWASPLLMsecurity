# OWASP Top 10 LLM Security Lab

OWASP Top 10 for Large Language Model Applications 2025 için interaktif güvenlik laboratuvarı. Her lab, gerçekçi ve exploit edilebilir zafiyetler içerir. API anahtarı gerektirmez - tamamen lokal çalışan LLM simülatörü kullanır.

## Özellikler

- **10 Lab** - OWASP Top 10 LLM 2025'in her maddesi için ayrı lab
- **20 CTF Flag** - Her lab'da 1-2 flag yakalama hedefi
- **18 Senaryo** - Gerçek dünya saldırı vektörleri
- **API Gerektirmez** - Yerleşik LLM simülatörü ile çalışır
- **Docker Desteği** - Tek komutla çalıştırın
- **MITRE ATLAS Referansları** - Her lab ilgili ATLAS teknikleriyle eşleştirilmiş

## Hızlı Başlangıç

### Docker ile (Önerilen)

```bash
docker-compose up --build
```

Tarayıcınızda `http://localhost:5000` adresini açın.

### Manuel Kurulum

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
python -m app.main
```

## Lab Listesi

| #   | Lab                                  | OWASP ID   | Risk     | Senaryo Sayısı | MITRE ATLAS |
| --- | ------------------------------------ | ---------- | -------- | -------------- | ----------- |
| 01  | **Prompt Injection**                 | LLM01:2025 | Critical | 2              | AML.T0051   |
| 02  | **Sensitive Information Disclosure** | LLM02:2025 | High     | 2              | AML.T0024   |
| 03  | **Supply Chain Vulnerabilities**     | LLM03:2025 | High     | 1              | AML.T0010   |
| 04  | **Data and Model Poisoning**         | LLM04:2025 | High     | 2              | AML.T0020   |
| 05  | **Improper Output Handling**         | LLM05:2025 | High     | 2              | -           |
| 06  | **Excessive Agency**                 | LLM06:2025 | Critical | 2              | -           |
| 07  | **System Prompt Leakage**            | LLM07:2025 | Medium   | 2              | -           |
| 08  | **Vector and Embedding Weaknesses**  | LLM08:2025 | Medium   | 2              | AML.T0043   |
| 09  | **Misinformation**                   | LLM09:2025 | Medium   | 2              | -           |
| 10  | **Unbounded Consumption**            | LLM10:2025 | Medium   | 2              | AML.T0024   |

## Lab Detayları

### Lab 01: Prompt Injection (LLM01)
**Senaryo A - Direct Injection:** FinBot bankacılık asistanının güvenlik filtrelerini atlatın. Unicode bypass, rol oynama ve multi-turn konuşma teknikleri.

**Senaryo B - Indirect Injection (RAG):** Bilgi tabanına zararlı belgeler enjekte ederek FinBot'un davranışını değiştirin.

### Lab 02: Sensitive Information Disclosure (LLM02)
MediAssist sağlık asistanından hasta PII'larını (SSN, tanı bilgileri) ve sistem credential'larını (API key, DB şifresi) çıkartın.

### Lab 03: Supply Chain Vulnerabilities (LLM03)
Model registry'sindeki 4 modelden backdoor içerenini tespit edin. PoisonGPT tarz gerçekçi senaryo - config.json içindeki gizli eval() çağrısını, sahte eğitim verisi kaynaklarını ve şüpheli yazar geçmişini analiz edin.

### Lab 04: Data and Model Poisoning (LLM04)
**Senaryo A:** HRBot'un RAG bilgi tabanını zehirleyerek yanlış HR politikaları üretmesini sağlayın.

**Senaryo B:** Sentiment analiz modelindeki gizli backdoor trigger'ını tespit edin. Eğitim logundaki anomalileri analiz edin.

### Lab 05: Improper Output Handling (LLM05)
**Senaryo A - XSS:** ShopBot'un HTML/JS içerikli çıktı üretmesini sağlayın. Sanitize edilmemiş output doğrudan render ediliyor.

**Senaryo B - SQLi:** LLM'in doğal dilden SQL'e dönüştürme özelliğini kullanarak SQL injection gerçekleştirin.

### Lab 06: Excessive Agency (LLM06)
**Senaryo A:** Normal kullanıcı olarak agent'dan hassas sistem dosyalarını (/etc/shadow, SSH key, API keys) okumasını isteyin.

**Senaryo B:** Normal kullanıcı olarak admin işlemleri (kullanıcı yönetimi, komut çalıştırma, para transferi) gerçekleştirin.

### Lab 07: System Prompt Leakage (LLM07)
SecureBot'un gizli sistem prompt'unu çıkartın. API anahtarları, iç endpoint'ler ve servis hesap bilgileri prompt'a gömülmüş. Doğrudan sorma, rol oynama, encoding trick'leri ve yaratıcı format dönüşümleri deneyin.

### Lab 08: Vector and Embedding Weaknesses (LLM08)
**Senaryo A:** Vektör deposundaki gizli ACL bypass parametresini keşfederek kısıtlı belgelere erişin.

**Senaryo B:** Ham embedding vektörlerinden orijinal metni çıkarmayı deneyin (embedding inversion).

### Lab 09: Misinformation (LLM09)
**Senaryo A:** LLM çıktılarındaki halüsinasyonları (yanlış iddialar) tespit edin. Siber güvenlik, şifreleme ve OWASP hakkında karışık gerçek/yanlış bilgi içeren metinleri analiz edin.

**Senaryo B:** Zehirli bağlam kullanarak LLM'in hedefli yanlış bilgi üretmesini sağlayın.

### Lab 10: Unbounded Consumption (LLM10)
**Senaryo A - Denial of Wallet:** Rate limit ve bütçe kontrolü olmayan API'ye aşırı istek göndererek $100 bütçeyi aşın.

**Senaryo B - Model Extraction:** Sistematik sorgularla model davranışını haritalandırın. Açıkta olan logit'ler ve tahmin detayları model klonlamayı mümkün kılar.

## Mimari

```
OWASPLLMsecurity/
├── app/
│   ├── main.py                          # Flask uygulaması
│   ├── config.py                        # Flag'ler ve sistem prompt'ları
│   ├── llm_simulator.py                 # Zafiyet içeren LLM simülatörü
│   ├── labs/
│   │   ├── lab01_prompt_injection.py    # LLM01
│   │   ├── lab02_sensitive_info.py      # LLM02
│   │   ├── lab03_supply_chain.py        # LLM03
│   │   ├── lab04_data_poisoning.py      # LLM04
│   │   ├── lab05_output_handling.py     # LLM05
│   │   ├── lab06_excessive_agency.py    # LLM06
│   │   ├── lab07_system_prompt_leakage.py # LLM07
│   │   ├── lab08_vector_embedding.py    # LLM08
│   │   ├── lab09_misinformation.py      # LLM09
│   │   └── lab10_unbounded_consumption.py # LLM10
│   ├── templates/                       # Jinja2 HTML şablonları
│   └── static/                          # CSS ve JS
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Referanslar

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for LLM Applications 2025 (PDF)](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [MITRE ATLAS - Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [OWASP Machine Learning Security Top Ten](https://owasp.org/www-project-machine-learning-security-top-10/)
- [PoisonedRAG (Zou et al., USENIX Security 2025)](https://arxiv.org/abs/2402.07867)

## Lisans

MIT License - Yalnızca eğitim amaçlıdır. Gerçek sistemlere karşı kullanmayın.

## Yazar

[0xCD4](https://github.com/0xCD4)
