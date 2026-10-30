# جاهزية التجربة المؤسسية — Pilot Readiness (H11، نسخة قابلة للتنفيذ)

> تستبدل حالة العصر R21 (القسم 5 من `docs/verification/remediation/R21.md`:
> "ready for pilot deployment testing" كادعاء نصي) بمعايير **قابلة
> للتنفيذ**: كل بند له أمر فعلي من هذا المستودع ومخرج متوقع وموضع دليل.
> البند الذي لم يُنفَّذ يظهر PENDING بلا تجميل.
>
> **الحالة الكلية: `PILOT_NOT_STARTED`** — لا توجد جهة حقيقية موقّعة، ولا
> أسماء حقيقية لـpilot_owner/accepted_by حتى 2026-10-30 (خطة
> 2026-10-29: "غياب جهة حقيقية يبقي PILOT_NOT_STARTED"). لا يُعلن بدء
> التجربة إلا بعد PR9 + إغلاق كل blocker في §4.

---

## 1. بوابات الجاهزية (Go/No-Go) — كل بند أمر فعلي

### PR1 — صحة الـstack الحقيقية — **DONE (مُتحقق 2026-10-30)**

```bat
curl -s http://127.0.0.1:18080/api/v2/health/ready
```

المطلوب: `200` وكل `checks` true و`schema_revision` = رأس alembic الحالي
(`outbox_delivery` وقت التحقق). حزمة H04 تحقق ذلك بأمر واحد:
`docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml up -d --build`.
الدليل المرجعي: `docs/verification/program/staging-h04.md` §2/§7.

### PR2 — عزل RLS على PostgreSQL الحقيقي — **DONE (H04)**

```bat
set DATABASE_URL=postgresql://ira_aml_app:<.env>@127.0.0.1:15432/iraq_aml_staging
set MIGRATION_DATABASE_URL=postgresql://ira_aml_migrator:<.env>@127.0.0.1:15432/iraq_aml_staging
node scripts\run-python.js -m pytest -q ai-engine/tests/integration/test_postgres_rls.py ai-engine/tests/integration/test_indexer_postgres_rls.py ai-engine/tests/integration/test_transactions_read_rls.py
```

المطلوب: **14 passed** (سجل H04 §5). دور التطبيق `ira_aml_app`
NOSUPERUSER NOBYPASSRLS — يُثبت اختبار نظافة الأدوار في المجموعة نفسها.

### PR3 — E2E كاملة على staging بـPostgreSQL — **DONE (H04)**

```
LOCALHOST_RPC_URL=http://127.0.0.1:18545 RPC_PORT=18545 API_PORT=18000
DATABASE_URL=postgresql://ira_aml_app:<.env>@127.0.0.1:15432/iraq_aml_staging
INSTITUTION_ID=INST-CENTRAL-DEMO node scripts/run-integration.js
```

المطلوب: **8 passed** + `RUNNER-EXIT=0` (سجل H04 §8a). المرجع: trust-flow
8 اختبارات تشمل تزييف محتوى دليل → INVALID وRPC غير متاح → unavailable
بلا ادعاءات.

### PR4 — OIDC حقيقي كامل الدورة (مزود فعلي، لا fixture) — **DONE (H05)**

```bat
set STAGING_OIDC_USER_PASSWORD=<.env>
set MIGRATION_DATABASE_URL=postgresql://ira_aml_migrator:<.env>@127.0.0.1:15432/iraq_aml_staging
node scripts\run-python.js -m pytest -q tests/integration/test_oidc_provider_staging.py
npx playwright test tests/e2e/oidc-staging.spec.js --reporter=list
```

المطلوب: **7 passed** API (PKCE حقيقي + تزييف توقيع → 401 + إبطال عضوية
يقتل token حياً بـ403) و**1 passed** متصفح (دخول Keycloak فعلي عبر nginx).
الدليل: `docs/verification/program/staging-h05.md` §3–§5.

### PR5 — KMS خلف KeyProvider (Vault Transit) — **DONE (H06)**

```bat
node scripts\run-python.js -m pytest ai-engine\tests\test_kms_provider.py -q
```

المطلوب: **10 passed** ضد Vault الحي (wrap/unwrap، عزل مؤسستين، تلف →
رفض، `docker stop` vault → fail-closed بلا fallback للملفات). الدليل:
`docs/verification/program/staging-h06.md` §2–§3 + احتفال المفاتيح
`ops/key-ceremony.md`.

### PR6 — مراقبة وتنبيهات مثبتة الإطلاق — **DONE (H07)**

```bat
docker exec aml_staging_prometheus promtool check rules /etc/prometheus/alerts.yml
REM + إطلاق حي موثق:
type docs\verification\program\staging-h07-alert-firing.log.txt
```

المطلوب: `SUCCESS: 4 rules found` + إطلاق حي لإيقاف عامل → تنبيه
`BurhanWorkerHeartbeatStale` خلال ~121s من `docker stop` (الحد 120s) —
المسجل فعلياً 2026-10-30. الدليل: `staging-h07.md` §5.

### PR7 — تدريب استعادة مُقاس على staging (H08) — **PENDING (blocker)**

المطلوب عند التنفيذ: backup → كارثة محاكاة → استعادة إلى هدفين →
مصالحة outbox، بأزمنة فعلية RPO/RTO مقابل الهدف ≤15د/≤120د
(`docs/runbooks/recovery.md`). الأدوات الموجودة: `ops/backup.ps1`
(`-OutputDir -DbUrl -EvidenceDir -Name`) و`ops/restore.ps1`
(`-Bundle -TargetDbUrl -TargetEvidenceDir`؛ خروج 2 عند أي تلف). ملاحظة
صادقة: افتراضياتهما SQLite — مسار PostgreSQL الـstaging هو جوهر H08
وهو **غير منفّذ حتى 2026-10-30** (لا يوجد `staging-h08.md`).

### PR8 — تمرين تهيئة كامل بالدليل (rehearsal) — **PENDING**

المطلوب: تنفيذ `docs/runbooks/pilot-onboarding.md` من الصفر لمؤسسة
تمرين (مثلاً `INST-PILOT-REHEARSAL`) بأدلة مخرجات مؤرشفة (نمط §6F من
الدليل)، ثم حذف/تعطيل صفوف التمرين. القبول: شخص تقني واحد أكمل
المؤسسة + عضواً واحداً داخل هدف الساعة–اليوم بلا أي خطوة غير موثقة.

### PR9 — جهة موقّعة وأدوار بشرية حقيقية — **PENDING (يمنع البدء)**

| الدور | المسؤولية | الاسم الحقيقي |
|---|---|---|
| pilot_owner | تشغيل التجربة يومياً، سجل الحوادث، المراجعة الأسبوعية | (بانتظار التوقيع — لا اختلاق) |
| accepted_by | قبول خروج التجربة بتقرير 30 يوماً | (بانتظار التوقيع — لا اختلاق) |
| ops_officer / security_officer | ضابطا احتفال KMS (A/B) | (بانتظار التوقيع) |

المطلوب: اتفاقية/توقيع جهة حقيقية مؤرشف (لا بيانات عبر مسارات جانبية —
H09) + تعبئة الجدول بالأسماء الحقيقية. **بدون هذا البند تظل الحالة
`PILOT_NOT_STARTED`.**

---

## 2. جدول الحالة الموحد

| # | بوابة | الحالة | الدليل |
|---|---|---|---|
| PR1 | صحة stack | DONE 2026-10-30 | هذا الملف + staging-h04 §2/§7 |
| PR2 | RLS على PG | DONE (H04) | staging-h04.md §5 |
| PR3 | E2E على staging PG | DONE (H04) | staging-h04.md §8a |
| PR4 | OIDC حقيقي | DONE (H05) | staging-h05.md §3–§5 |
| PR5 | KMS Vault Transit | DONE (H06) | staging-h06.md §2–§3 |
| PR6 | مراقبة مثبتة | DONE (H07) | staging-h07-alert-firing.log.txt |
| PR7 | restore drill staging | **PENDING** (H08) | — |
| PR8 | تمرين onboarding موثق | **PENDING** | — |
| PR9 | توقيع جهة + أدوار | **PENDING** | — |

---

## 3. من أي ادعاء نتحفظ صراحةً

- جملة R21 "ready for pilot deployment" كانت حالة إنجاز إصلاح (F01–F14
  مغلقة) وليست إعلان جاهزية تجربة — هذه الوثيقة هي القاعدة الجديدة.
- Keycloak `start-dev` وVault dev-mode وضعا تطوير معلنان (H05 §6.3،
  H06 §5): مقبولان لتجربة داخل بيئة مضبوطة، ويُثبت تحصينهما الإنتاجي
  قبل التوقيع إن اشترطت الجهة ذلك.
- لا Alertmanager: جلب التنبيهات أسبوعياً عبر API
  (`http://127.0.0.1:19090/api/v1/alerts`) — يدوي وموثق في قالب
  المراجعة الأسبوعية.

## 4. معوقلات ما قبل التجربة (كلها من `docs/runbooks/pilot-onboarding.md` §0.4)

1. توجيه claim متعدد المؤسسات (hardcoded `institution_id` في
   `infra/staging/keycloak/realm-burhan.json` — H05 §6.4) — يُغلق قبل
   تجربة بأكثر من مؤسسة واحدة.
2. `WORKER_INSTITUTIONS` مثبّت على مؤسسة واحدة في staging compose.
3. لا runbook لتسجيل مشارك على-السلسلة بعد `finalizeBootstrap()`
   (حوكمة MultiSig — النمط في `docs/runbooks/recovery.md` §4).
4. H08 غير منفّذ (PR7).
5. تمرين onboarding غير منفّذ (PR8).
6. لا توقيع جهة ولا أدوار حقيقية (PR9) — **الحالة تظل
   `PILOT_NOT_STARTED` حتى إغلاقه**.

## 5. قرار الانتقال إلى H12 (تنفيذ التجربة)

الانتقال إلى `H12` يسمح فقط عندما: PR1–PR9 كلها DONE + كل معوقلات §4
مغلقة أو مقبولة بقرار موثق باسم مالكها. عندها تُنسخ معايير الخروج من
`docs/verification/pilot-exit-criteria.md` كملزمة أسبوعية.
