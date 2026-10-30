# Runbook: تهيئة مؤسسة جديدة للتجربة المؤسسية (H11 — Pilot Onboarding)

> **الهدف:** جعل تهيئة مؤسسة جديدة مهمة موثقة يقوم بها شخص تقني واحد في
> ساعة–يوم واحد، بكل خطوة بأمر فعلي ومخرج متوقّع من هذا المستودع بالضبط —
> لا أوامر مختلقة.
>
> **الحالة الصادقة: PILOT_NOT_STARTED** — لا توجد جهة حقيقية موقّعة حتى
> تاريخ إصدار هذا الدليل (2026-10-30). كل ما يلي هو إجراء التهيئة الجاهز
> للتنفيذ، وليس دليلاً على أن تجربة بدأت. لا تُعلن بداية تجربة قبل توقيع
> الجهة (H11/H12 في خطة 2026-10-29).
>
> **الجمهور:** مشغّل تقني واحد (pilot_owner الفني) مع وصول إلى ملف
> `infra/staging/.env` (متجاهل من Git) وحاسبة المحفظة للعضو المُهيَّأ.
>
> **البيئة المرجعية:** staging stack الحقيقية (H04–H07) على فرع `main` —
> شُغّلت وتحققت فعلياً بتاريخ 2026-10-30: readiness **200** عبر nginx،
> Keycloak realm `burhan` جاهز، Prometheus/Prometheus targets up، رأس
> المخطط `outbox_delivery`.

---

## 0. المتطلبات السابقة والقيود

### 0.1 تشغيل الحزمة (stack)

```bat
docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml up -d --build
```

كل الأسرار تُقحم من `infra/staging/.env` (gitignored؛ القالب
`infra/staging/.env.example`)، وأي متغير ناقص يفشل تشغيل compose صراحةً.

### 0.2 فحص الجاهزية (مخرج فعلي مُتحقق منه 2026-10-30)

```bat
curl -s http://127.0.0.1:18080/api/v2/health/ready
```

المتوقع: `200` و `{"status":"ready", ... "checks":{"database":true,
"migrations":true,"kms_vault":true,"evm_rpc":true,"ml_engine":true,
"policy_service":true}, "schema_revision":"outbox_delivery", ...}`.

خريطة المنافذ المعلَنة (كلها loopback فقط — لا شيء على 0.0.0.0):

| الخدمة | Container | منفذ المضيف |
|---|---|---|
| nginx/frontend (الواجهة الوحيدة للمتصفح) | `aml_staging_frontend` | 127.0.0.1:18080 |
| Keycloak (realm `burhan`) | `aml_staging_keycloak` | 127.0.0.1:18081 |
| PostgreSQL 16 | `aml_staging_postgres` | 127.0.0.1:15432 |
| Hardhat EVM (chain 31337) | `aml_staging_evm` | 127.0.0.1:18545 |
| Vault Transit (KMS، dev-mode) | `aml_staging_vault` | 127.0.0.1:18200 |
| Prometheus / Grafana | `aml_staging_prometheus` / `..._grafana` | 19090 / 18300 |

### 0.3 قواعد صارمة (من R10/R11 — غير قابلة للتفاوض)

- **المحرك لا يزرع شيئاً أبداً على PostgreSQL (R11):** صف المؤسسة والعضويات
  واجب مُشغِّل (migration/owner role) — حرفياً كما في
  `ops/keycloak/provision_staging_operator.py`.
- **العضوية تُفحص على كل طلب (R10):** تعطيل صف العضوية يمنع الـtoken الحي
  من الطلب التالي (403) — إثبات H05 §3 (test 7).
- لا سر في أي ملف مُلتزم: كلمات المرور و`STAGING_ANCHOR_SIGNER_PRIVATE_KEY`
  و`STAGING_VAULT_DEV_ROOT_TOKEN_ID` كلها في `infra/staging/.env` فقط.

### 0.4 المعوقلات المسبقة للتجربة (PRE-PILOT BLOCKERS — لا تتجاهلها)

هذه بنود موثقة يجب إغلاقها قبل يوم التجربة الأول؛ أشر إليها في
`docs/verification/pilot-readiness.md` لا هنا فقط:

1. **توجيه claim متعدد المؤسسات:** `institution_id` حالياً قيمة
   **hardcoded على مستوى الـclient** في `infra/staging/keycloak/realm-burhan.json`
   (mapper بقيمة `INST-CENTRAL-STAGING`) — disclosed في H05 §6.4. إضافة
   مؤسسة *ثانية* تتطلب mapper لكل-مستخدم (user attribute) وإعادة استيراد
   الـrealm (حجم `staging_keycloak_data` جديد — انظر §6.2 من H05). مؤسسة
   واحدة موقّعة = مقبول؛ أكثر من واحدة = blocker.
2. **العمال مثبّتون على مؤسسة واحدة:** `INSTITUTION_ID` /
   `WORKER_INSTITUTIONS` في `infra/staging/docker-compose.staging.yml`
   (خدمتا worker-anchor/worker-indexer) يُقمان من `STAGING_INSTITUTION_ID`
   — مؤسسة جديدة تتطلب توسيع هذه القائمة وإعادة تشغيل العاملين.
3. **تسجيل محفظة العضو على السلسلة:** `POST /wallet/verify` يُثبت المشارك
   على-السلسلة عبر RoleManager (عنوان staging:
   `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512` من
   `infra/staging/runtime-config.staging.json`)؛ محفظة غير مسجلة = فشل ربط
   (fail-closed). التسجيل الأولي يجري داخل `scripts/deploy.js` عبر
   `multiSig.bootstrapParticipants(...)` (6 مشاركين: SUPER_ADMIN + 3
   AUDITOR + OPERATOR + REGULATOR) ثم `finalizeBootstrap()` يُبطل سلطة
   bootstrap نهائياً — إضافة مشارك بعد ذلك هي حوكمة MultiSig بأربع عيون
   (نمط `replaceParticipant` — انظر `docs/runbooks/recovery.md` §4) ولا
   يوجد لها runbook مخصص بعد → **blocker توثيقي** قبل يوم التجربة.
4. **H08 غير منفّذ بعد:** لا يوجد `staging-h08.md` في
   `docs/verification/program/` — نسخ/استعادة PostgreSQL الـstaging
   (`ops/backup.ps1` افتراضياته SQLite) ما زالت مهمة H08.
5. **Keycloak `start-dev` وVault dev-mode:** وضعا تطوير معلنان بصدق
   (H05 §6.3، H06 §5)؛ إعادة تشغيل Vault dev-mode تفقد المفاتيح
   (fail-closed، لا fallback). التحصين الإنتاجي مطلوب قبل توقيع التجربة.
6. **لا Alertmanager:** التنبيهات تُطلق في Prometheus (API/UI/TSDB) فقط —
   جلب التنبيهات في المراجعة الأسبوعية يكون عبر API (H07 §9).

---

## 1. المرحلة A — إنشاء المؤسسة في سجل المؤسسات

**المصدر:** نمط one-shot `db-seed-institutions` في
`infra/staging/docker-compose.staging.yml` (H04، commits `dfb183d` +
`138bd14`): INSERT بصفة مالك السجل `ira_aml_migrator`، و`institutions`
جدول RLS-ENABLED (غير FORCEd) لذا يملك المالك الحق في كتابته.

**قواعد التسمية:** `id` مؤسسة يجب ألا يحتوي الفاصل المحجوز `--` (خانق
KmsProvider — تسمية مفاتيح Transit تعتمد عليه، انظر `ops/key-ceremony.md`
§1)، وينطبق نمط `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. حقل `created_at`
إلزامي في الـINSERT (لا server default — H04 §6.7، إصلاح `138bd14`).

**الطريقة (سجل حقيقي، اسم حقيقي):** حدد `INSTITUTION_ID` الجديد (مثال
الشرح: `INST-PILOT-01`) ونفّذ INSERT بصفة المالك. كلمة مرور المالك من
`infra/staging/.env` (`STAGING_MIGRATOR_PASSWORD`) — لا تُطبع ولا تُلزم:

```bat
REM اقرأ كلمة المرور إلى متغير جلسة من الملف المتجاهل (لا تكتبها في أي ملف):
for /f "usebackq tokens=1,* delims==" %A in (`findstr /b "STAGING_MIGRATOR_PASSWORD=" infra\staging\.env`) do set "PGPASS=%B"

docker exec -e PGPASSWORD=%PGPASS% aml_staging_postgres psql -U ira_aml_migrator -d iraq_aml_staging ^
  -v ON_ERROR_STOP=1 ^
  -c "INSERT INTO institutions (id, name, is_active, created_at) VALUES ('INST-PILOT-01', 'الجهة الحقيقية الموقّعة (الاسم كما في الاتفاقية)', true, now()) ON CONFLICT (id) DO NOTHING;"
```

**المخرج المتوقع:** `INSERT 0 1` (أو `INSERT 0 0` إن كان الصف موجوداً —
الـone-shot idempotent). تحقق:

```bat
docker exec aml_staging_postgres psql -U postgres -d iraq_aml_staging -t ^
  -c "SELECT id, name, is_active FROM institutions WHERE id = 'INST-PILOT-01';"
```

> **لماذا ليس `docker compose run db-seed-institutions`؟** الـone-shot
> الملتزم يزرع `${STAGING_INSTITUTION_ID:-INST-CENTRAL-STAGING}` بالاسم
> العام "Staging Institution" فقط؛ مؤسسة تجربة حقيقية تُدخل بالاسم الرسمي
> الموقّع في اتفاقية البيانات، لذا الـINSERT الصريح أعلاه هو النمط ذاته
> بنفس الدور ونفس الأعمدة.

---

## 2. المرحلة B — تسجيل الأعضاء في Keycloak + صفوف العضوية

**المصدر:** الـone-shot الملتزم `keycloak-provision-operator`
(`ops/keycloak/provision_staging_operator.py`، service
`keycloak-provision-operator` في staging compose — H05 `df0356e`). السكربت
idempotent بالكامل: create-or-update مستخدم Keycloak مع attribute
`institution_id`، ثم upsert صف عضوية ACTIVE بصفة `ira_aml_migrator` تحت
سياق المستأجر transaction-local (`set_config('app.current_institution_id', ..., true)`
— نفس نمط مجموعة RLS).

### 2.1 عضو واحد لكل تشغيل (أعد التشغيل لكل عضو)

لكل عضو `N`: قيم في جلسة shell (أو أضفها مؤقتاً لجلسة الـrun عبر `-e`)،
ثم:

```bat
docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml ^
  run --rm ^
  -e STAGING_OIDC_USERNAME=member-n ^
  -e STAGING_OIDC_USER_EMAIL=member-n@institution.example ^
  -e STAGING_OIDC_USER_PASSWORD=<كلمة مرور مولّدة — لا تُخترع، ولّدها:>
  -e STAGING_OIDC_MEMBERSHIP_ROLE=<ROLE> ^
  -e STAGING_INSTITUTION_ID=INST-PILOT-01 ^
  keycloak-provision-operator
```

ولّد كلمات المرور (من `infra/staging/.env.example` نفسه):

```bat
node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
```

**الأدوار المتاحة** (`RoleEnum` في `ai-engine/app/schemas/identity.py`):
`SUPER_ADMIN` / `AUDITOR` / `OPERATOR` / `REGULATOR` (الافتراضي في
السكربت `OPERATOR`). ملاحظة فعلية: `REGULATOR` للقراءة فقط —
`POST /api/v2/imports/transactions` يرفضه 403 صراحة
(`ai-engine/app/routes/v2/transactions.py`).

**المخرج المتوقع** (نمط سجلات H05 §3 الحقيقية):

```text
[provisioner] keycloak operator ready: realm=burhan username=member-n attributes=institution_id:INST-PILOT-01 (password NOT printed)
[provisioner] membership created: role=OPERATOR active=true
[provisioner] done: sub=<UUID>          ← subject العضو؛ ليس سراً (يظهر في كل token)
```

إعادة تشغيل لنفس العضو = `membership re-activated (idempotent re-run)`.
تحذير السلوك الموثق: السكربت يعطّل العضويات النشطة *الأخرى لنفس المؤسسة*
(subs ميتة بعد مسح حجم Keycloak) — انظر §6.2 من H05؛ في تجربة متعددة
الأعضاء هذا السطر `deactivated N stale membership row(s)` يجب فهمه: هو
يعطّل كل من لم يعُد يمكن مصادقته من realm المُستورد حديثاً، وليس كل من
سواه في هذا التشغيل — إذا شغّلت العضو n2 فلن يُعطّل n1 (نفس sub حي).

### 2.2 مسار REST الأصلي (ماذا يفعل السكربت فعلياً — للمراجعة اليدوية)

1. Admin token: `POST {KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token`
   بـ`admin-cli` + `STAGING_KEYCLOAK_ADMIN_USERNAME/PASSWORD` (من
   `.env`؛ السكربت يصبر حتى 3 دقائق لأول إقلاع).
2. المستخدم: `GET/POST /admin/realms/burhan/users` (create 201/409) مع
   `attributes: {"institution_id": ["INST-PILOT-01"]}` و`emailVerified: true`.
3. كلمة المرور: `PUT /admin/realms/burhan/users/{id}/reset-password`
   (`{"type":"password","temporary":false,"value":...}` — لا تُطبع أبداً).
4. العضوية: INSERT في `memberships`
   `(id='mem_'||16hex, institution_id, sub, role, email, is_active=true, created_at=now())`
   بصفة `ira_aml_migrator` بعد `SELECT set_config('app.current_institution_id', :inst, true)`.

> **حدود Realm-as-code:** تعديلات `realm-burhan.json` (مثل mapper
> institution_id لكل مستخدم عند معالجة blocker 0.4-1) لا تنطبق إلا بإعادة
> استيراد realm عبر حجم `staging_keycloak_data` جديد، ثم يعيد الـone-shot
> إنشاء المشغّل idempotently (H05 §6.2 — مُثبت بسجلات ثلاث تشغيلات).

---

## 3. المرحلة C — ربط محفظة كل عضو (challenge → verify)

**المصدر:** `ai-engine/app/routes/v2/identity.py` (R10) + السكيما
`ai-engine/app/schemas/identity.py` + إثبات H05 §3 (tests 6).

**الشرط المسبق الحقيقي:** محفظة العضو يجب أن تكون **مشاركاً نشطاً
على-السلسلة** في RoleManager staging
(`0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512` — من
`infra/staging/runtime-config.staging.json`؛ المشاركون الستة سجلهم
`scripts/deploy.js` عبر `bootstrapParticipants`). محفظة غير مسجلة →
`/wallet/verify` يفشل fail-closed (403/400، لا ربط). إضافة مشارك بعد
`finalizeBootstrap()` = حوكمة MultiSig (blocker 0.4-3)؛ أعضاء التجربة
الأوائل يُربطون على محافظ المشاركين الستة المقيّدين مسبقاً.

الخطوات لكل عضو (الtoken = بعد دخول OIDC من §5، أو عبر أي Bearer حي
لنفس العضو):

**1) Challenge (SIWE, EIP-4361, single-use, 5 دقائق TTL):**

```bat
curl -s -X POST http://127.0.0.1:18080/api/v2/wallet/challenge ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"wallet_address\":\"0xMemberWallet42hex\",\"chain_id\":31337}"
```

المتوقع `200`:
`{"challenge_id":"...","nonce":"...","message":"<EIP-4361 ... domain ... chain 31337>","expires_at":"..."}`.
لاحظ `chain_id=31337` (CHAIN_ID staging فعلي — H05: القيمة الافتراضية
1337 ترفض كل ربط).

**2) التوقيع:** العضو يوقّع `message` بـEIP-191 من محفظته (MetaMask على
RPC `http://127.0.0.1:18545`، chain 31337 — القيم المعلنة في
`runtime-config.staging.json` للواجهة). لا يوجد مسار توقيع من جانب
الخادم — السلسلة هي حدود الإثبات.

**3) Verify (استهلاك CAS للتحدي + إثبات RoleManager + ربط):**

```bat
curl -s -X POST http://127.0.0.1:18080/api/v2/wallet/verify ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"challenge_id\":\"<من الخطوة 1>\",\"signature\":\"0x<130 hex>\"}"
```

المتوقع `200`:
`{"bound":true,"wallet_address":"0x...","institution_id":"INST-PILOT-01","participant_id":"0x...","role":"OPERATOR","authorization_generation":1}`.

دلالات فعلية: التحدي أحادي الاستخدام (توقيع ثانٍ بنفس challenge_id =
رفض)، الدور والتوليد يقرآن من العضوية/السلسلة، والربط يخزن في
`wallet_bindings` (تحقق SQL للقراءة فقط:
`SELECT institution_id, role, wallet_address, authorization_generation FROM wallet_bindings WHERE institution_id='INST-PILOT-01';`).
تدوير المحفظة لاحقاً = نفس التدفق (توليد تفويض جديد يُبطل التواقيع
القديمة — R10).

---

## 4. المرحلة D — تسجيل مفتاح KMS للمؤسسة

**المصدر:** `ops/key-ceremony.md` (H06) — احتفال شخصين إلزامي، كل
العمليات عبر `KmsProvider` (`ai-engine/app/security/kms_provider.py`)
على Vault Transit. **للمؤسسة الجديدة جيل `k1` كامل بالضبط كما في §3–§4
من الاحتفال** (لن يُلخَّص هنا إلا ما يخص onboarding):

1. **Vault up** (إن لم يكن) بـoverride الـKMS:

```bat
docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml -f infra/staging/docker-compose.kms.yml up -d vault
docker ps --filter name=aml_staging_vault --format "{{.Names}} {{.Status}} {{.Ports}}"
```

المتوقع: `aml_staging_vault Up ... 127.0.0.1:18200->8200/tcp` (loopback فقط).

2. **إنشاء جيل المفتاح** (ضابطا الاحتفال A/B — أسماء حقيقية في سجل
   الاحتفال، لا اختلاق):

```bat
node scripts\run-python.js -c "from app.security.kms_provider import KmsProvider; from app.config import settings; p=KmsProvider(settings.VAULT_ADDR, settings.VAULT_TOKEN); p._ensure_transit(); print(p.create_key_generation('INST-PILOT-01','k1'))"
```

ينشئ مفتاحي Transit: `<inst>--sig--k1` (ed25519 للتوقيع) و
`<inst>--dek--k1` (aes256-gcm96 لغلاف DEK) — idempotent.

3. **المفتاح العام لسجل الثقة:** `print(p.public_key_b64('INST-PILOT-01','k1'))`
   → base64 لـ32-byte Ed25519 public (نفس صيغة سجل ثقة R05) — يسجل في
   سجل الثقة المؤسسي (مادة عامة)، ويوثق بصمته (أول 8 حروف) في سجل الاحتفال.

4. **سجل المفتاح الحالي خارج الكود:** عدّل `infra/staging/.env`
   (gitignored): `STAGING_KMS_CURRENT_KEYS={"INST-PILOT-01":"k1"}`
   ثم أعد إنشاء المحرك بالـoverride: `docker compose ... -f ...kms.yml up -d ai-engine`.
   السجل هو *الوحيد* الذي يقرر "الحالي" — لا ملف مؤشر ولا تعديل كود.

5. **تحقق قبل الإعلان الانتهاء:** `node scripts\run-python.js -m pytest ai-engine\tests\test_kms_provider.py -q`
   → **10 passed** ضد Vault الحي (wrap/unwrap، عزل مؤسستين، تلف → رفض،
   fail-closed عند توقف KMS).

**حدود صادقة (H06 §5):** Vault dev-mode — إعادة تشغيل الحاوية تفقد
مفاتيح Transit (الأظرفة بعد ذلك ترفض fail-closed بـValueError، لا
كارثة صمت). قبل التوقيع على تجربة حقيقية: KMS مُدار دُور (managed/durable — AWS KMS / Azure Key Vault) أو Vault HA
مُحكم خلف نفس واجهة `KeyProvider`. سجل الاحتفال يُلزم بدون أسرار
(قالب §7 في `ops/key-ceremony.md`).

---

## 5. المرحلة E — أول دخول OIDC (قائمة تحقق لكل عضو)

**المصدر:** عقد §8 (R10) + `infra/staging/keycloak/realm-burhan.json` +
إثبات H05 (متصفح حقيقي f8a860f).

1. المتصفح → `http://127.0.0.1:18080` (nginx — الواجهة الوحيدة).
2. بوابة R13 تُعيد التوجيه إلى
   `http://127.0.0.1:18081/realms/burhan/protocol/openid-connect/auth?client_id=iraq-aml-frontend&response_type=code&code_challenge_method=S256&...&redirect_uri=http://127.0.0.1:18080/auth/callback&scope=openid profile email&state=...`
   (هذه المعاملات assert عليها E2E الـPlaywright
   `tests/e2e/oidc-staging.spec.js` فعلياً).
3. دخول بنموذج Keycloak (username/password من §2) — PKCE S256 مُفعّل
   إجبارياً (`pkce.code.challenge.method=S256`؛ لا implicit ولا password
   grant في الـrealm).
4. callback → تبادل الكود → توجيه الكونسول. تحقق API:

```bat
curl -s http://127.0.0.1:18080/api/v2/identity/me -H "Authorization: Bearer %TOKEN%"
```

المتوقع `200`: `sub` (UUID العضو)، `issuer=http://127.0.0.1:18081/realms/burhan`،
`institution_id`، `role`، وعند اكتمال §3: `participant_id` +
`wallet_address` + `authorization_generation`.

5. **السلوكيات السلبية المطلوب رؤيتها مرة على الأقل** (هي ضمانات R10):
   - بلا token → `401 {"detail":"Missing Authorization Bearer token"}` (المسار الديمو غير قابل للوصول في institutional).
   - token بتوقيع مُزوَّر → `401` (تحقق فعلي ضد JWKS الحي — `test_tampered_token_is_401_not_503`).
   - تعطيل عضوية العضو (`UPDATE memberships SET is_active=false WHERE sub='...'` بصفة المالك تحت سياق المستأجر) → **نفس الـtoken الحي يعطي 403 على الطلب التالي**، ثم إعادة التفعيل → 200 (نمط H05 test 7).

---

## 6. المرحلة F — اختبار الدخان: المؤسسة حيّة فعلاً

المسار الكامل (نفس مسار trust-flow E2E — `tests/e2e/trust-flow.spec.js`
— لكن بالـtoken المؤسسي الحقيقي):

1. **استيراد CSV** (`REGULATOR` يُرفض 403 هنا — استخدم OPERATOR/AUDITOR):

```bat
curl -s -X POST "http://127.0.0.1:18080/api/v2/imports/transactions?source=IQD_CSV" ^
  -H "Authorization: Bearer %TOKEN%" -H "Expect:" ^
  -F "file=@shared\fixtures\banking-iqd-demo.csv"
```

المتوقع `201` مع ملخص الدفعة (`TransactionImportResponse`). الملف
النموذجي الحقيقي في المستودع: `shared/fixtures/banking-iqd-demo.csv` —
نفس الـfixture الذي يستخدمه E2E (test 1.5 في trust-flow: 10 صفوف،
`status: COMPLETED`). إعادة استيراد نفس `external_id`s تُرفض كنسخ مكررة
(سلوك connector — H04 §6.8).

2. **قراءة نموذج القراءة:** `curl -s "http://127.0.0.1:18080/api/v2/transactions?limit=10" -H "Authorization: Bearer %TOKEN%"`
   → `200` وعدد صفوف ≥ المستورد (تحت FORCE RLS — قراءة H04 المُصلحة
   `7677d31`).

3. **إنشاء قضية:** `POST /api/v2/cases` بجسم
   `{"case_number":"PILOT-<inst>-0001","title":"...","severity":"..."}` →
   `201` (Idempotency-Key اختياري — تكراره بنفس النطاق = 409).

4. **دليل وتحقق:** ارفع دليل القضية (رفع multipart إلى
   `POST /api/v2/evidence/cases/{case_id}` — مسار الإرسال في
   `ai-engine/app/routes/v2/evidence.py`، `201` مع
   `Idempotency-Key` اختياري):

```bat
curl -s -X POST http://127.0.0.1:18080/api/v2/evidence/cases/<CASE_ID> ^
  -H "Authorization: Bearer %TOKEN%" ^
  -F "file=@path\to\evidence.pdf"
```

ثم تحقق V3 ضد لقطة السلسلة المثبتة:

```bat
curl -s -X POST http://127.0.0.1:18080/api/v3/evidence/verify ^
  -H "Authorization: Bearer %TOKEN%" -H "Content-Type: application/json" ^
  -d "{\"caseId\":\"<CASE_ID>\",\"evidenceIds\":[\"<EVIDENCE_ID>\"]}"
```

المتوقع `200` ونتيجة VERIFIED ضد لقطة السلسلة المثبتة (V3 + سجل الثقة).
اختبار السالب الحقيقي: محتوى دليل مُعدَّل → INVALID (E2E test 2.1
"Altered Evidence Content Rejected as Invalid").

5. **العمال والسلسلة حيّة:**

```bat
curl -s "http://127.0.0.1:19090/api/v1/query?query=burhan_worker_heartbeat_age_seconds"
curl -s "http://127.0.0.1:19090/api/v1/query?query=burhan_outbox_oldest_pending_age_seconds"
```

المتوقع (قيم حية 2026-10-30): heartbeat ≈ 1–5 ثوانٍ لكل role، outbox
age ≈ 0. الدليل pipeline يستنزف (COMPLETED/SUBMITTED تنمو، PENDING لا
تتجاوز 300s — تنبيه `BurhanOutboxOldestPendingStale`).

6. **سجل الإنجاز:** أرشف مخرجات 1–5 في ملف تحقق التهيئة (نمط
   `docs/verification/program/`) — هذه هي الحلقة المغلقة التي تثبت أن
   المؤسسة حيّة، لا ادعاء.

---

## 7. التقدير الزمني الواقعي (شخص واحد تقني)

| المرحلة | الوقت |
|---|---|
| 0. Stack جاهز + فحوص | 15 دقيقة (بعد أول build) |
| A. صف المؤسسة | 10 دقائق |
| B. N أعضاء Keycloak + عضويات | ~5 دقائق/عضو |
| C. ربط المحافظ (العضو يوقّع) | ~5 دقائق/عضو |
| D. احتفال KMS (شخصان) | 30–45 دقيقة |
| E. أول دخول + سلوكيات سلبية | 15 دقيقة/عضو |
| F. دخان كامل + أرشفة | 20 دقيقة |

المجموع لمؤسسة بثلاثة أعضاء: **~2–3 ساعات** لشخص واحد + الضابط الثاني
للاحتفال — داخل هدف القبول (ساعة–يوم). هذا التقدير *لا* يشمل إغلاق
معوقلات §0.4.
