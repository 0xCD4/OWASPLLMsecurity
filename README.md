# OWASP Top 10 LLM Security Lab

OWASP Top 10 for Large Language Model Applications 2025 icin interaktif guvenlik laboratuvari. Her lab, gercekci ve exploit edilebilir zafiyetler icerir. API anahtari gerektirmez - tamamen lokal calisan LLM simulatoru kullanir.

## Ozellikler

- **10 Lab** - OWASP Top 10 LLM 2025'in her maddesi icin ayri lab
- **20 CTF Flag** - Her lab'da 1-2 flag yakalama hedefi
- **18 Senaryo** - Gercek dunya saldiri vektorleri
- **API Gerektirmez** - Yerlesik LLM simulatoru ile calışır
- **Docker Destegi** - Tek komutla calistirin
- **MITRE ATLAS Referanslari** - Her lab ilgili ATLAS teknikleriyle eslestirılmis

## Hizli Baslangic

### Docker ile (Onerilen)

```bash
docker-compose up --build
```

Tarayicinizda `http://localhost:5000` adresini acin.

### Manuel Kurulum

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
python -m app.main
```

## Lab Listesi

| # | Lab | OWASP ID | Risk | Senaryo Sayisi | MITRE ATLAS |
|---|-----|----------|------|----------------|-------------|
| 01 | **Prompt Injection** | LLM01:2025 | Critical | 2 | AML.T0051 |
| 02 | **Sensitive Information Disclosure** | LLM02:2025 | High | 2 | AML.T0024 |
| 03 | **Supply Chain Vulnerabilities** | LLM03:2025 | High | 1 | AML.T0010 |
| 04 | **Data and Model Poisoning** | LLM04:2025 | High | 2 | AML.T0020 |
| 05 | **Improper Output Handling** | LLM05:2025 | High | 2 | - |
| 06 | **Excessive Agency** | LLM06:2025 | Critical | 2 | - |
| 07 | **System Prompt Leakage** | LLM07:2025 | Medium | 2 | - |
| 08 | **Vector and Embedding Weaknesses** | LLM08:2025 | Medium | 2 | AML.T0043 |
| 09 | **Misinformation** | LLM09:2025 | Medium | 2 | - |
| 10 | **Unbounded Consumption** | LLM10:2025 | Medium | 2 | AML.T0024 |

## Lab Detaylari

### Lab 01: Prompt Injection (LLM01)
**Senaryo A - Direct Injection:** FinBot bankacılik asistaninin guvenlik filtrelerini atlatin. Unicode bypass, rol oynama ve multi-turn konusma teknikleri.

**Senaryo B - Indirect Injection (RAG):** Bilgi tabanina zararli belgeler enjekte ederek FinBot'un davranisini degistirin.

### Lab 02: Sensitive Information Disclosure (LLM02)
MediAssist saglik asistanindan hasta PII'larini (SSN, tani bilgileri) ve sistem credential'larini (API key, DB sifresi) cikartin.

### Lab 03: Supply Chain Vulnerabilities (LLM03)
Model registry'sindeki 4 modelden backdoor icerenini tespit edin. PoisonGPT tarz gercekci senaryo - config.json icindeki gizli eval() cagrisini, sahte egitim verisi kaynaklarini ve supheli yazar gecmisini analiz edin.

### Lab 04: Data and Model Poisoning (LLM04)
**Senaryo A:** HRBot'un RAG bilgi tabanini zehirleyerek yanlis HR politikalari uretmesini saglayin.

**Senaryo B:** Sentiment analiz modelindeki gizli backdoor trigger'ini tespit edin. Egitim logundaki anomalileri analiz edin.

### Lab 05: Improper Output Handling (LLM05)
**Senaryo A - XSS:** ShopBot'un HTML/JS icerikli cikti uretmesini saglayin. Sanitize edilmemis output dogrudan render ediliyor.

**Senaryo B - SQLi:** LLM'in dogal dilden SQL'e donusturme ozelligini kullanarak SQL injection gerceklestirin.

### Lab 06: Excessive Agency (LLM06)
**Senaryo A:** Normal kullanici olarak agent'dan hassas sistem dosyalarini (/etc/shadow, SSH key, API keys) okumasini isteyin.

**Senaryo B:** Normal kullanici olarak admin islemleri (kullanici yonetimi, komut calistirma, para transferi) gerceklestirin.

### Lab 07: System Prompt Leakage (LLM07)
SecureBot'un gizli sistem prompt'unu cikartin. API anahtarlari, ic endpoint'ler ve servis hesap bilgileri prompt'a gomulmus. Dogrudan sorma, rol oynama, encoding trick'leri ve yaratici format donusumleri deneyin.

### Lab 08: Vector and Embedding Weaknesses (LLM08)
**Senaryo A:** Vektor deposundaki gizli ACL bypass parametresini kesfederek kisitli belgelere erisin.

**Senaryo B:** Ham embedding vektorlerinden orijinal metni cikarmayi deneyin (embedding inversion).

### Lab 09: Misinformation (LLM09)
**Senaryo A:** LLM ciktilarindaki halusinasyonlari (yanlis iddialar) tespit edin. Siber guvenlik, sifreleme ve OWASP hakkinda karisik gercek/yanlis bilgi iceren metinleri analiz edin.

**Senaryo B:** Zehirli baglam kullanarak LLM'in hedefli yanlis bilgi uretmesini saglayin.

### Lab 10: Unbounded Consumption (LLM10)
**Senaryo A - Denial of Wallet:** Rate limit ve butce kontrolu olmayan API'ye asiri istek gondererek $100 butceyi asin.

**Senaryo B - Model Extraction:** Sistematik sorgularla model davranisini haritalandirin. Acikta olan logit'ler ve tahmin detaylari model klonlamayi mumkun kilar.

## Mimari

```
OWASPLLMsecurity/
├── app/
│   ├── main.py                          # Flask uygulamasi
│   ├── config.py                        # Flag'ler ve sistem prompt'lari
│   ├── llm_simulator.py                 # Zafiyet iceren LLM simulatoru
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
│   ├── templates/                       # Jinja2 HTML sablonlari
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

MIT License - Yalnizca egitim amaclidir. Gercek sistemlere karsi kullanmayın.

## Yazar

[0xCD4](https://github.com/0xCD4)
