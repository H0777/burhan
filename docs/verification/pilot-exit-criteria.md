# معايير خروج التجربة المؤسسية — Pilot Exit Criteria (H11، قابلة للقياس)

> كل معيار هنا: العتبة + **كيف يُقاس** (استعلام/مقياس فعلي من H04–H07 في
> هذا المستودع) + موضع الدليل الأسبوعي. لا معيار نصي بلا قياس.
>
> **الحالة: `PILOT_NOT_STARTED`.** هذه المعايير لا تُطبق إلا بعد بوابة
> `docs/verification/pilot-readiness.md` §5 (توقيع جهة + إغلاق
> المعوقلات). أثناء التجربة تُراجع **أسبوعياً** وتُحفظ النتائج في
> `docs/verification/pilot/weekly-NN.md` (القالب:
> `docs/verification/pilot/weekly-review-template.md`)، وأي خرق يُسجَّل
> في `docs/verification/pilot/incident-log-template.md`.

الرموز أدناه: `<INST-A>` = مؤسسة التجربة الموقّعة، `%TOKEN%` = Bearer
token حي لدور مراجع، وكلمات المرور تُقرأ من `infra/staging/.env`
(gitignored) ولا تُطبع ولا تُلزم.

---

## X1 — صفر أحداث عبور مؤسسات (cross-tenant)

- **العتبة:** `0` عبر كامل التجربة (30 يوماً).
- **كيف يُقاس:**
  1. **اختبار الانحدار الأسبوعي** (نفس بطارية H04 على PostgreSQL الحقيقي):
     ```
     set DATABASE_URL=postgresql://ira_aml_app:<.env>@127.0.0.1:15432/iraq_aml_staging
     set MIGRATION_DATABASE_URL=postgresql://ira_aml_migrator:<.env>@127.0.0.1:15432/iraq_aml_staging
     node scripts\run-python.js -m pytest -q ai-engine/tests/integration/test_transactions_read_rls.py ai-engine/tests/integration/test_postgres_rls.py
     ```
     المطلوب: أخضر كامل — وقراءة المستأجر الأجنبي **0 صف** هي تأكيد صريح
     في `test_transactions_read_rls.py` (مسار HTTP كامل: استيراد 201 +
     قائمة ≥10 + قارئ أجنبي 0).
  2. **مسبار RLS مباشر** (قراءة فقط، دور التطبيق الأقل صلاحية، سياق مستأجر
     آخر):
     ```bat
     docker exec -e PGPASSWORD=<.env STAGING_APP_PASSWORD> aml_staging_postgres psql -U ira_aml_app -d iraq_aml_staging -c "SELECT set_config('app.current_institution_id','OTHER-INST',true); SELECT count(*) FROM cases; SELECT count(*) FROM transactions;"
     ```
     المطلوب: `0` و `0` — FORCE RLS يُخفي كل شيء دون السياق الصحيح
     (سلوك H04 §6.2 المُصلح والمعتمد بالاختبار).
- **فشل المعيار = خرق فوري:** إيقاف الكتابة + حادثة SEV-1 + قرار موثق (§X6).

## X2 — صفر فقد دليل

- **العتبة:** كل دليل مُرسل موجود وقابل للجلب والتثبيت؛ `0` حدث outbox
  خارج الحالة الناجحة أسبوعياً.
- **كيف يُقاس:**
  1. **مصالحة outbox** (SQL أسبوعي — المصدر: جدول `outbox` R08 الذي
     تراقبه `burhan_outbox_oldest_pending_age_seconds`):
     ```bat
     docker exec -e PGPASSWORD=<.env> aml_staging_postgres psql -U postgres -d iraq_aml_staging -c "SELECT status, count(*) FROM outbox GROUP BY status;" -c "SELECT count(*) AS stuck FROM outbox WHERE status IN ('PENDING','PROCESSING') AND created_at < now() - interval '300 seconds';"
     ```
     المطلوب أسبوعياً: `stuck = 0` (نافذة 300s هي حد تنبيه
     `BurhanOutboxOldestPendingStale` في `ops/monitoring/alerts.yml`)؛
     كل صف يدخل الحالة النهائية COMPLETED/SUBMITTED.
  2. **ربط دليل↔anchor:** كل `evidence_objects` للتجربة له صف anchor
     مكتمل:
     ```sql
     SELECT count(*) FROM evidence_objects e WHERE NOT EXISTS (SELECT 1 FROM evidence_anchors a WHERE a.institution_id = e.institution_id AND a.evidence_id = e.evidence_id AND a.status = 'COMPLETED');
     ```
     المطلوب: `0`.
  3. **إثبات جلب:** عينة أسبوعية (≥5 أدلة) تُجلب عبر
     `GET /api/v2/evidence/{evidence_id}` → `200` و`sha256_hash` مطابق،
     وتُحقَّق عبر `POST /api/v3/evidence/verify` → VERIFIED.

## X3 — صفر توقيع مزور مقبول

- **العتبة:** `0` نتيجة VERIFIED لغير موقّع سجل الثقة؛ كل محاولة تزييف
  تُرفض وتُسجَّل.
- **كيف يُقاس:**
  1. **مسبار تزييف أسبوعي:** عدّل بايتاً واحداً في ملف دليل مسلَّم وأعد
     `POST /api/v3/evidence/verify` (نفس نداء §X2.3) → المطلوب
     **INVALID** (النتيجة ثلاثية صارمة — `unavailable` لا تمزج أبداً)،
     وهو نفس المسار الذي يثبته E2E test 2.1
     ("Altered Evidence Content Rejected as Invalid").
  2. **إثبات مسار التوقيع:** تحقق عدم-تزييف التوقيع على مستوى JWT أسبوعياً
     (token بتوقيع مقلوب → **401** لا 503) —
     `tests/integration/test_oidc_provider_staging.py::test_tampered_token_is_401_not_503`
     (H05).
  3. تحقق المحرّك للتوقيعات حصراً ضد Ed25519 لسجل الثقة الخارجي بلا أي
     fallback غير آمن (بوابة G1 — `docs/verification/g1-trust.md`؛
     المُحقق دون اتصال `scripts/verify-evidence-export.py` يُشغَّل على
     تصدير الأدلة مرة خلال التجربة).
- **القبول:** عدد الاستثناءات المقبولة من الحالات المرفوضة = 0؛ أي
  VERIFIED مشكوك فيه → SEV-1.

## X4 — تراكم outbox ضمن الحد أسبوعياً

- **العتبة:** أقدم حدث pending ≤ **300 ثانية** باستمرار (حد التنبيه
  H07)؛ الاستثناء الوحيد نافذة صيانة موثقة بحادثة؛ **كل إطلاق تنبيه له
  صف سجل حوادث** (بلا استثناء).
- **كيف يُقاس** (في كل مراجعة أسبوعية — PromQL عبر Prometheus
  `http://127.0.0.1:19090`):
  1. أعمق تراكم خلال الأسبوع:
     `/api/v1/query?query=max_over_time(burhan_outbox_oldest_pending_age_seconds[7d])`
  2. عدد إطلاقات تنبيه التراكم:
     `/api/v1/query?query=count_over_time(ALERTS{alertname="BurhanOutboxOldestPendingStale",alertstate="firing"}[7d])`
  3. صحة العمال: `min_over_time(burhan_worker_heartbeat_age_seconds[7d])`
     لا تتجاوز 120s (تنبيه `BurhanWorkerHeartbeatStale`).
  القيم الحية وقت إعداد هذه المعايير (2026-10-30): outbox age `0`،
  heartbeat ≈ 1.3–1.7s — أي أن العتبة فوق سلوك التشغيل الفعلي المُقاس.
- **ملاحظة صادقة:** لا Alertmanager (H07 §9) — الجلب يدوي عبر API/لوحة
  Grafana `burhan-staging-health` (127.0.0.1:18300) ويُثبت بلقطة قيم في
  `weekly-NN.md`.

## X5 — تدريب استعادة ناجح واحد خلال التجربة

- **العتبة:** drill واحد مكتمل داخل الـ30 يوماً: backup → كارثة محاكاة →
  استعادة إلى هدف جديد → مصالحة outbox → إعادة عمال، بنتيجة: خروج 0 +
  تطابق سجلات + RPO ≤ **15 دقيقة** وRTO ≤ **120 دقيقة** (أهداف
  `docs/runbooks/recovery.md`).
- **كيف يُقاس:** `ops\backup.ps1` ثم `ops\restore.ps1 -Bundle <bundle.zip>
  -TargetDbUrl <هدف> -TargetEvidenceDir <مجلد>` (أزمنة wall-clock تُسجَّل
  في الدليل). الأدوات ترفض أي تلف بخروج 2 (حماية bit-rot — F12/R16).
- **حد صادق:** مسار PostgreSQL الـstaging لهذا الـdrill هو **مهمة H08
  غير المنفّذة** (لا يوجد `staging-h08.md`) — يُنفَّذ H08 قبل التجربة ثم
  يُعاد تنفيذ drill واحد منها خلال التجربة وفق هذه المعايير. الدليل:
  `docs/verification/pilot/restore-drill.md` (يُنشأ عند التنفيذ).

## X6 — حوكمة الخروق والقرار

- أي خرق لـX1–X5: **إيقاف الكتابة** (freeze) + صف في سجل الحوادث +
  تقييم + قرار موثق (استمرار/إيقاف) باسم pilot_owner — لا تجاوز (قاعدة
  H12 حرفياً).
- الخروج بعد 30 يوماً: تقرير بأرقام X1–X5 الفعلية + توقيع
  pilot_owner/accepted_by الحقيقيين → `READY_FOR_COMMERCIAL` أو قائمة
  بنود إصلاح. التجربة لا تساوي جاهزية تجارية — القرار منفصل (H12/H13).

---

## 6. ملخص القياس الأسبوعي (يُلزم في weekly-NN.md)

| المعيار | القياس | العتبة |
|---|---|---|
| X1 عبور مستأجرين | بطارية RLS + مسبار 0-صف | 0 |
| X2 فقد دليل | `stuck=0` + ربط anchor + عينة جلب | 0 |
| X3 توقيع مزور | مسبار تزييف → INVALID + 401 tampered JWT | 0 مقبول |
| X4 تراكم outbox | `max_over_time(...[7d])` + عدّاد إطلاق | ≤300s، كل إطلاق له حادثة |
| X5 استعادة | drill واحد ناجح بأزمنة | RPO ≤15د / RTO ≤120د |
| X6 حوكمة | كل خرق → freeze + قرار موثق | لا تجاوز |

**التوقيعات عند الخروج (أسماء حقيقية فقط — فارغة الآن لأن التجربة لم
تبدأ):**

- pilot_owner: ______________ التاريخ: ______
- accepted_by: ______________ التاريخ: ______
- النتيجة: ☐ READY_FOR_COMMERCIAL ☐ قائمة إصلاح (المرفق: ______)
