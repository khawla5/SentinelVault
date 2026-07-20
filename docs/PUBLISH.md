# نشر SecureVault على GitHub و LinkedIn

دليل خطوة بخطوة. الأوامر تُكتب في الترمنال داخل مجلد المشروع.

---

## المرحلة 0 — تنظيف الملفات قبل الرفع (مهم)

المجلد فيه بقايا من محاولة قديمة (مجلد `backend/app` نصف مكتمل + ملفات مؤقتة).
نحذفها حتى يكون المستودع نظيفاً واحترافياً:

```bash
cd ~/Desktop/"Password Manager"

# حذف بقايا المحاولة القديمة المكرّرة
rm -rf backend/app backend/venv backend/__pycache__ backend/password_manager.db
rm -f  backend/test_hash.py backend/docker-compose.yml backend/run.sh \
       backend/.env.example backend/requirements.txt
rm -f  package-lock.json
```

> ملاحظة أمان: ملف `.env` (فيه أسرارك) مُتجاهَل تلقائياً بواسطة `.gitignore` ولن يُرفع. تأكد بهذا الأمر — يجب أن يطبع `.env`:
> ```bash
> git check-ignore .env
> ```

---

## المرحلة 1 — تجهيز أول commit

```bash
git add -A                      # يضيف كل الملفات الجديدة والمعدّلة
git status                      # (اختياري) يعرض ما سيُرفع — تأكد أن .env غير موجود
git commit -m "SecureVault: encrypted password manager with threat detection and web UI"
git branch -M main              # يسمّي الفرع الرئيسي main
```

كل أمر وماذا يفعل:
- `git add -A` = يجهّز جميع التغييرات للحفظ.
- `git commit -m "..."` = يحفظ لقطة من المشروع برسالة توضّح المحتوى.
- `git branch -M main` = يضمن أن اسم الفرع `main` (المتعارف عليه في GitHub).

---

## المرحلة 2 — إنشاء المستودع على GitHub

1. افتح https://github.com/new
2. **Repository name:** `securevault`
3. **Description:** `Encrypted password manager with malware & threat detection (AES-256-GCM, Argon2id, FastAPI).`
4. اختر **Public** (ليظهر في ملفك).
5. **لا** تختر "Add a README" ولا "Add .gitignore" — عندنا منها بالفعل.
6. اضغط **Create repository**.
7. انسخ رابط المستودع، سيكون بالشكل:
   `https://github.com/USERNAME/securevault.git`

---

## المرحلة 3 — ربط ورفع

```bash
git remote add origin https://github.com/USERNAME/securevault.git
git push -u origin main
```

- `git remote add origin ...` = يربط مشروعك المحلي بمستودع GitHub (استبدل `USERNAME`).
- `git push -u origin main` = يرفع الكود.

**إذا طلب منك تسجيل الدخول:** GitHub لم يعد يقبل كلمة مرور الحساب في الترمنال. أسهل حلّين:
- **GitHub Desktop** (واجهة رسومية، الأسهل للمبتدئ): حمّله من desktop.github.com، سجّل دخولك، ثم File → Add Local Repository → اختر مجلد المشروع → Publish.
- أو **Personal Access Token:** من GitHub → Settings → Developer settings → Personal access tokens → Generate → انسخه واستخدمه بدل كلمة المرور عند الطلب.

---

## المرحلة 4 — إضافته إلى LinkedIn

### أ) كقسم "Projects" في ملفك
1. افتح ملفك في LinkedIn → **Add profile section**.
2. **Recommended → Add featured** (لإبراز رابط GitHub) أو **Additional → Add projects**.
3. املأ:
   - **Project name:** SecureVault — Encrypted Password Manager with Threat Detection
   - **Project URL:** رابط مستودع GitHub
   - **Description:** (النص الجاهز بالأسفل)

### ب) النص الجاهز (انسخه كما هو)

> **SecureVault — Encrypted Password Manager with Malware & Threat Detection**
>
> A defensive-security portfolio project: a password manager that stores
> credentials using AES-256-GCM authenticated encryption with keys derived via
> Argon2id, while monitoring the host for credential-stealing malware behaviour.
>
> Highlights:
> • Zero-knowledge design — the master password is never stored; the vault key
>   is derived at login and wiped from memory on logout.
> • AES-256-GCM per-entry encryption with random IVs and authentication tags.
> • Argon2id master-password hashing + brute-force lockout.
> • Have I Been Pwned leak check via k-Anonymity (only 5 hash chars leave the device).
> • Threat scanner: suspicious-process detection, clipboard-hijack detection,
>   file-integrity monitoring, and process-injection (RWX-memory) heuristics.
> • FastAPI backend (SQLite / Supabase-ready), 36 automated tests, and a custom
>   web UI with English/Arabic (RTL) localization, dark/light themes, and a
>   theme color system — no external front-end libraries.
>
> Stack: Python · FastAPI · SQLAlchemy · SQLite/PostgreSQL · cryptography ·
> argon2-cffi · psutil · HTML/CSS/JS.
> GitHub: <your repo link>

### ج) مهارات (Skills) أضِفها إلى ملفك
مهارات فعلاً موجودة في المشروع (أضِفها بثقة):
`Cryptography` · `AES Encryption` · `Argon2 Password Hashing` · `Secure Coding` ·
`Threat Detection` · `File Integrity Monitoring` · `Python` · `FastAPI` ·
`REST APIs` · `SQLAlchemy` · `SQLite` · `PostgreSQL` · `Behavior Monitoring` ·
`Application Security` · `Unit Testing`

### د) منشور LinkedIn (اختياري)

> 🔐 Just shipped SecureVault — an encrypted password manager I built to go
> beyond a basic CRUD app and into real defensive security.
>
> It uses AES-256-GCM + Argon2id, a zero-knowledge key model, a Have I Been
> Pwned leak check, and a threat scanner that detects suspicious processes,
> clipboard hijacking, file tampering, and process-injection indicators. Backend
> in FastAPI with 36 tests; custom bilingual (EN/AR + RTL) UI with theming.
>
> Code + docs on GitHub 👇  #cybersecurity #Python #cryptography #infosec

---

## ملاحظة صدق مهمة لسيرتك
اذكر فقط ما نفّذته فعلاً. المشروع يُظهر: التشفير، Argon2، كشف التهديدات (Heuristics)،
FastAPI، الاختبارات، وواجهة متعددة اللغات. أمّا YARA و Machine Learning والهندسة
العكسية فهي "أعمال مستقبلية" مذكورة في الـ README — لا تدرجها كمهارات متقنة بعد.
