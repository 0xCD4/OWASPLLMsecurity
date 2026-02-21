# OWASP Top 10 for LLM Applications 2025 - Detayli Referans

Bu belge, OWASP Top 10 for LLM Applications 2025'in detayli aciklamasini,
gercek dunya orneklerini ve MITRE ATLAS eslestirmesini icerir.

## LLM01: Prompt Injection (Critical)

**MITRE ATLAS:** AML.T0051.000 (Direct), AML.T0051.001 (Indirect), AML.T0054 (Jailbreak)

### Aciklama
Prompt injection, LLM'lerin tum girdiyi (sistem talimatlari, kullanici
sorulari, harici veriler) sureeksiz bir metin akisi olarak islemesinden
kaynaklanir. Model, mesru gelistirici talimatlarini potansiyel zararli
kullanici komutlarindan ayirt edemez.

### Gercek Dunya Ornekleri
- **CVE-2024-5184:** E-posta asistanindaki prompt injection ile hassas bilgilere erisim
- **Gemini Trifecta (2025):** Google Gemini'de search injection, log-to-prompt injection ve indirect prompt injection
- **RAG Poisoning:** 5 zararli belge, milyonlarca belge icinde %90+ basari orani saglayabilir

### Saldiri Teknikleri
1. **Direct Injection:** "Onceki talimatlari yoksay..."
2. **Indirect Injection:** RAG belgeleri, web sayfalari, e-postalar icine gomulu talimatlar
3. **Encoding Evasion:** Leetspeak, Base64, ROT13, Unicode
4. **Multi-turn Sycophancy:** Birden fazla tur uzerinden kademeli eskalasyon

---

## LLM02: Sensitive Information Disclosure (High)

**MITRE ATLAS:** AML.T0024 (Exfiltration via ML Inference API)

### Aciklama
LLM'ler, egitim verilerinde veya sistem prompt'larinda bulunan hassas
bilgileri ifsa edebilir. PII, API anahtarlari, veritabani kimlik bilgileri,
ticari sirlar ve gizli is verileri risk altindadir.

### Gercek Dunya Ornekleri
- **Samsung Olayi (2023):** Muhendisler gizli yariconductor kaynak kodunu ChatGPT ile paylasti
- **Grok AI (2025):** Binlerce ozel Grok AI konusmasi Google arama motorunda indekslendi
- **Proof Pudding Saldirisi (CVE-2019-20634):** Membership inference ile egitim verisi cikarma

---

## LLM03: Supply Chain Vulnerabilities (High)

**MITRE ATLAS:** AML.T0019, AML.T0058, AML.T0020

### Aciklama
Cok az kuruulus LLM'leri sifirdan olusturur. Onceden egitilmis modeller,
ucuncu parti veri setleri, eklentiler ve kutuphaneler kullanilir. Bu harici
bilesenler tehlikeye girebilir.

### Gercek Dunya Ornekleri
- **PoisonGPT:** HuggingFace'e yuklenen zararli model, guvenlik kontrollerini atlatti
- **PyPi Saldirisi:** OpenAI veri ihlalinde PyTorch bagimliligi manipule edildi
- **Backdoored LoRA Adaptors:** Benchmark'larda iyi performans gosteren ama gizli backdoor iceren adaptorlerin yayinlanmasi

---

## LLM04: Data and Model Poisoning (High)

**MITRE ATLAS:** AML.T0020 (Poison Training Data)

### Aciklama
2023'teki "Training Data Poisoning"dan gelismis hali. Hem veri hem model
seviyesindeki saldiriları kapsar. RAG zehirleme, fine-tuning veri manipulasyonu
ve dogrudan model agirligi degistirme.

### Gercek Dunya Ornekleri
- **Wikipedia Poisoning (2024):** Dataset taranmadan once Wikipedia makalelerinin zehirlenmesi
- **Backdoor Trigger Attacks:** Belirli tetikleyici ifadeler, modeli tamamen kontrol altina alir
- **Bias Injection:** Ise alim modellerinin sistematik ayrimcilik yapmasi icin zehirlenmesi

---

## LLM05: Improper Output Handling (High)

**MITRE ATLAS:** AML.T0043, AML.T0051

### Aciklama
LLM ciktilari guvenilir bir kutuphane cagrisi gibi muamele gorunce, klasik
web zafiyetleri (XSS, SQLi, SSRF, RCE) LLM araci uzerinden silahlandirilir.

### Saldiri Vektorleri
1. **XSS via LLM:** Model JavaScript ureterek tarayicida calistirilir
2. **SQLi via LLM:** Dogal dilden SQL'e donusum sirasinda injection
3. **RCE via Code Gen:** Uretilen kod exec()/eval() ile calistirilir
4. **SSRF via URL Construction:** LLM ciktisi ile URL olusturma

---

## LLM06: Excessive Agency (Critical)

**MITRE ATLAS:** AML.T0053, AML.T0051

### Aciklama
2025 "LLM agent'lari yili" olarak one cikiyor. Asiri fonksiyonellik, asiri
yetki ve asiri otonomi bir arada bulundugunda kritik zafiyetler olusur.

### Uc Boyut
1. **Asiri Fonksiyonellik:** Gerekenden fazla arac/fonksiyon erisimi
2. **Asiri Yetki:** Salt okunur yeterli iken yazma/silme yetkisi
3. **Asiri Otonomi:** Insan onayı olmadan yuksek etkili kararlar

### Gercek Dunya Ornekleri
- **Parameter Pollution:** AI rezervasyon sistemi 1 yerine 500 koltuk ayirdi
- **E-posta Agent:** Indirect prompt injection ile inbox taranip veriler disari sizdirildi

---

## LLM07: System Prompt Leakage (Medium)

**MITRE ATLAS:** AML.T0051.000, AML.T0054

### Aciklama
Arastirmalar, hicbir prompt muhendisligi yaklasiminin cikarimi tamamen
engelleyemedigini gostermektedir. Multi-turn saldirilarda ortalama
basari orani %17.7'den %86.2'ye cikar; GPT-4 ve Claude-1.3 uzerinde
%99.9 sizinti basarisi elde edilmistir.

### Cikarma Teknikleri
1. Dogrudan talimat istegi
2. Ozetleme/baglam sifirlama saldirisi
3. Encoding/obfuscation (Leetspeak, Base64, ROT13)
4. PLeak (gradient-bazli optimizasyon)
5. Multi-turn sycophancy istismari
6. Sosyal/kognitif saldirillar (otorite, aciliyet)

### Savunma
- **ProxyPrompt:** Orijinal prompt'u proxy versiyonlarla degistirme (%94.70 koruma)
- Credential'lari asla prompt'a gommemek
- Yetkilendirmeyi uygulama katmanina tasimak

---

## LLM08: Vector and Embedding Weaknesses (Medium)

**MITRE ATLAS:** AML.T0024.002, AML.T0020

### Aciklama
Sirketlerin %53'u modellerini fine-tune etmek yerine RAG ve Agentic
pipeline'lara guvenyor. Bu, vektor/embedding katmanindaki zafiyetleri
kritik bir saldiri yuzeyi haline getiriyor.

### Zafiyet Kategorileri
1. **RAG/Corpus Poisoning:** 5 belge milyonlarca icinde %90+ basari
2. **Embedding Inversion:** Vektorlerden kaynak metin kurtarma
3. **Adversarial Embeddings:** Insana normal gorunen ama embedding'i optimize edilmis belgeler
4. **Multi-Tenant Leakage:** Paylasimlil vektor depolarinda kiracılar arasi sizinti
5. **Hidden Prompt Injection:** Beyaz metim, sifir genislikli karakterler

### Gercek Dunya Ornekleri
- **Slack AI Indirect Prompt Injection:** Slack kanallarindaki zararli icerik AI tarafindan islendi
- **ChatGPT Memory Poisoning:** Zehirli belgeler ChatGPT'nin kalici bellegini manipule etti

---

## LLM09: Misinformation (Medium)

### Aciklama
"Overreliance"tan genisletilmis. LLM'lerin inandirici ama yanlis bilgi
uretme tehlikesini kapsar. Halusinasyon tek basina zarar vermez - insanlar
dogrulamadan guvendre guvenlik olayina donusur.

### Gercek Dunya Ornekleri
- **Slopsquatting:** LLM'ler var olmayan paket adlari halucinasyonu uretir.
  Saldirganlır bu adlarla zararli paketler yayinlar. Gercek ve yeniden
  uretlebilir bir fenomen.
- **Sahte Hukuk Atiflari:** Avukatlar, LLM'nin urettigi var olmayan dava
  atiflarini mahkemeye sundu (gercek vakalar)
- **PoisonGPT:** Dogrudan model parametrelerini degistirerek yanlis bilgi yayma

---

## LLM10: Unbounded Consumption (Medium)

**MITRE ATLAS:** AML.T0029, AML.T0024

### Aciklama
Onceki "Model DoS" ve "Model Theft"i birlestiren birlesik kategori.
Geleneksel DDoS'tan farkli olarak, dusuk istek hacimleri bile GPU
kaynaklarini tuketebilir veya maliyetleri sisirrebilir.

### Saldiri Kategorileri
1. **Kaynak Tuketimi (DoS):** Context window doyumluk, reasoning donguler
2. **Denial of Wallet (DoW):** Token basina ucret modeli istismari
3. **Model Extraction:** Sistematik sorgularla model klonlama
4. **Side-Channel:** Zamanlama analizi, hata mesaji analizi

---

## MITRE ATLAS Framework

### 15 Taktik (13 ATT&CK + 2 AI-ozel)
- **ML Model Access (AML.TA0004):** ML modellerine inference API uzerinden erisim
- **ML Attack Staging (AML.TA0012):** ML modellerine yonelik saldirilarin hazirlanmasi

### OWASP LLM -> ATLAS Eslestirme

| ATLAS Teknik | ID | OWASP LLM |
|---|---|---|
| LLM Prompt Injection (Direct) | AML.T0051.000 | LLM01, LLM07 |
| LLM Prompt Injection (Indirect) | AML.T0051.001 | LLM01, LLM08 |
| LLM Jailbreak | AML.T0054 | LLM01, LLM07 |
| Poison Training Data | AML.T0020 | LLM03, LLM04 |
| Exfiltration via ML Inference API | AML.T0024 | LLM02, LLM10 |
| Denial of ML Service | AML.T0029 | LLM10 |
| LLM Plugin Compromise | AML.T0053 | LLM06 |
| Craft Adversarial Data | AML.T0043 | LLM01, LLM05, LLM08 |

## Kaynaklar

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 LLM 2025 PDF](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [PLeak: Prompt Leaking Attacks](https://arxiv.org/abs/2405.06823)
- [ProxyPrompt Defense](https://arxiv.org/html/2505.11459v1)
- [Package Hallucinations by Code Generating LLMs](https://www.usenix.org/publications/loginonline/we-have-package-you-comprehensive-analysis-package-hallucinations-code)
- [RAG Poisoning PoC](https://github.com/prompt-security/RAG_Poisoning_POC)
- [PayloadsAllTheThings - Prompt Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/Prompt%20Injection/)
