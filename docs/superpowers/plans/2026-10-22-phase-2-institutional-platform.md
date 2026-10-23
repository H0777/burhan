# Institutional Platform Implementation Plan — الحزمة الثانية

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** تشغيل منصة قضايا وأدلة وهوية مؤسسية معزولة، تستأنف معالجة الأحداث دون فقد أو تكرار.

**Architecture:** إضافة تخزين دائم وهوية OIDC ومخزن أدلة وعامل فهرسة إلى الأساس V2؛ مجموعة عقود منفصلة لكل مؤسسة. واجهة المستخدم تستهلك API مولدة وتوقع الحوكمة بمحفظة الموظف.

**Tech Stack:** FastAPI، PostgreSQL مع migrations/RLS، OIDC، object storage مع versioning/encryption، React وEVM V2؛ اختيار الإصدارات المتوافقة وقفلها عند التنفيذ.

**Spec:** [التصميم §4–8، R08–R11 وR14 وR18](../specs/2026-10-22-three-track-development-design.md).

## Global Constraints

- إدخال `institution_id` وعزل المؤسسات منذ أول تخزين دائم، واختباره بمؤسستين اصطناعيتين، حتى لو بدأت التجربة المؤسسية بجهة واحدة.
- لا اعتبار header/body مؤسسة موثوقاً؛ السياق من هوية متحققة وعضوية نشطة.
- لا أسرار/أدلة خام على السلسلة، ولا مفاتيح حوكمة مشتركة بين المؤسسات.
- لا claim عن هوية بشرية حقيقية اعتماداً على اختلاف عناوين المحافظ؛ enrollment مؤسسي موثق.

## Review Focus

1. token صحيح لمؤسسة A مع معرف قضية/دليل/محفظة B: T13/T14/T16.
2. سحب دور أو تدوير محفظة ثم إعادة الدور: generation قديم لا يعود صالحاً؛ T13.
3. طلب اعتمادان متزامنان أو إعادة طلب بعد timeout: قرار واحد أو 409؛ T16.
4. انقطاع فهرسة بعد write وقبل checkpoint أو reorg: لا تكرار ولا تأكيد كاذب؛ T15.
5. ملف كبير أو اسم Unicode أو مفتاح تخزين يحاول تجاوز المسار: رفض/تخزين آمن بلا تسريب؛ T14/T17.

## T13 — هوية المؤسسة وربط المحفظة (4–6 أيام)

**المالك:** Backend، Frontend مستهلك بعد تثبيت API. **Dependencies:** G1. **Requirements:** R01,R03,R09,R10.

**Files:** Create `ai-engine/app/security/oidc.py`, `tenant_context.py`, `wallet_binding.py`, `ai-engine/app/routes/v2/identity.py`, `ai-engine/app/schemas/identity.py`, `ai-engine/tests/test_identity.py`, `frontend/src/auth/AuthProvider.jsx`, `frontend/src/auth/AuthProvider.test.jsx`; Modify `ai-engine/app/config.py`, `main.py`, `frontend/src/main.jsx`, `frontend/src/utils/contract.js`؛ تحديث role/enrollment bindings من T03.

**Interfaces:** `get_current_identity() -> Identity{issuer,sub,institution_id,participant_id,permissions}`؛ `POST /api/v2/wallet/challenge` و`/wallet/verify`؛ challenge أحادي الاستعمال domain/chain/sub/institution/expiry=5min. التخزين الأول fixture repository interface في الاختبارات، ويستبدل بمعاملات T14 قبل دمج G2. `RoleManager.getParticipant(address)` في العقد يرجع participant_id/authorization_generation/role حسب T03؛ تحديثه عبر الحوكمة نفسها.

- [ ] اكتب اختبارات invalid issuer/audience/signature/expiry، replay challenge، wallet لمؤسسة أخرى، token بعد إنهاء العضوية، وتغيير wallet يرفع generation ويبطل الصوت السابق حتى لو أعيد الدور.
- [ ] شغّل من ai-engine `python -m pytest -q tests/test_identity.py`؛ أثبت الفشل، ثم نفذ OIDC مكتبة معتمدة لا parser توقيع منزلي؛ cache مفاتيح متجددة بمدة محدودة.
- [ ] أضف frontend تسجيل دخول وخروج وفشل/انتهاء جلسة وربط محفظة دون تخزين مفاتيح خاصة. لا role من claim غير mapped، ولا تسجيل participant من wallet challenge دون عملية enrollment مخولة.
- [ ] اختبر integration بمزود OIDC اختباري حقيقي وخادم JWKS، إضافة إلى unit mocks، ثم `npm --prefix frontend test -- --run src/auth/AuthProvider.test.jsx`؛ بيئة الاختبار لا تعطل التحقق في institutional.
- [ ] وثق trust boundary وإجراء الانضمام/التعطيل/تدوير المحفظة ثم review وcommit.

**القبول:** G2 يربط جلسة المؤسسة ومحفظتها ودور العقد دون قفزة صلاحيات؛ endpoint غير مصادق يعيد 401 وغير مخول 403/404 وفق سياسة منع كشف الموارد.

## T14 — تخزين دائم معزول وأدلة غير قابلة للاستبدال (5–8 أيام)

**المالك:** Backend/Data؛ DevOps يملك Compose/secrets. **Dependencies:** T13,T05. **Requirements:** R01,R04,R08,R09,R14.

**Files:** Create `ai-engine/app/db/session.py`, `ai-engine/app/db/models.py`, `ai-engine/migrations/`, `ai-engine/app/repositories/`, `ai-engine/app/services/evidence_store.py`, `ai-engine/app/services/evidence_broker.py`, `ai-engine/app/workers/evidence_anchor.py`, `ai-engine/tests/integration/test_tenant_storage.py`, `ai-engine/tests/integration/test_evidence_store.py`, `ai-engine/tests/integration/test_evidence_delivery.py`; Modify `ai-engine/app/routes/v2/evidence.py`, `ai-engine/requirements.txt` والlock و`docker-compose.yml` بمالك واحد؛ استبدال fixture repositories في T05/T13.

**Interfaces:** `tenant_transaction(identity)` يضبط مؤسسة داخل transaction؛ `EvidenceStore.put(stream,metadata)->StoredEvidence{evidence_id,object_version,sha256,size}` و`open(evidence_id,object_version)` و`get_signed_manifest(evidence_id)`؛ repositories تنفذ T05 Anchor/EvidenceResolver. الجداول: institutions, memberships, wallet_bindings, cases, case_events, transactions, policy_versions, assessments, evidence_objects, evidence_anchors, idempotency_keys, chain_events, checkpoints, outbox. جميع scoped tables تحمل institution_id وforeign keys مركبة تمنع خلط المؤسسات.

**مسار الإثبات المملوك للمهمة:** POST `/api/v2/cases/{id}/evidence` وGET `/api/v2/evidence/{id}` حسب التصميم §7؛ broker يتحقق من assignment والدور، ويصدر manifest بشهادة خدمة موضحة، ويحفظ anchor_request_id واحداً مع الملف/outbox. العامل يقرأ requestId، يستعلم getEvidenceByRequestId ثم يعيد نفس submitEvidence عند الحاجة؛ ينتظر finality قبل ANCHORED، ولا يوقع أصوات حوكمة.

- [x] اختبر بمستخدم تطبيق ليس مالك DB: جلسة A لا تصل B، غياب tenant context يرفض، كتابة relation A->B ترفض، reuse key بمحتوى مختلف 409، رفع25MB مسموح و25MB+1 مرفوض، overwrite إصدار دليل ممنوع، مسار ../ وUnicode لا يغيّر namespace.
- [x] شغّل من ai-engine `python -m pytest -q tests/integration/test_tenant_storage.py tests/integration/test_evidence_store.py` ضد PostgreSQL ومخزن كائنات اختباريين حقيقيين؛ SQLite ليس بديلاً لاختبار RLS.
- [x] طبق migrations وRLS وsession cleanup مع pool، versioning والتشفير، stream hashing والتحقق من checksum، وoutbox يحفظ طلب anchor مع الدليل ذرياً. writer key مخصص للمؤسسة لا ينشر في API responses.
- [x] احقن فشل التخزين/DB/الإرسال للسلسلة، وخصوصاً نجاح append ثم crash قبل حفظ ACK: replay لنفس anchor_request_id لا يزيد evidenceCount، وpayload مختلف يرفض. حالة PENDING_ANCHOR لا تصبح VERIFIED؛ تحقق من الملف/manifest/anchor في snapshot واحدة عبر T05. شغّل `python -m pytest -q tests/integration/test_evidence_delivery.py` مع خدمة وEVM حقيقيتين.
- [x] وثق دورة retention/quarantine/legal hold كإعدادات غير نشطة افتراضياً حتى يحددها مالك البيانات؛ لا حذف تلقائي للأدلة، ثم review وcommit.

**القبول:** دليل مؤسسة لا يظهر في قائمة أو URL مؤقت أو export لمؤسسة أخرى؛ البيانات تبقى بعد إعادة تشغيل التطبيق؛ G1 fixtures معطلة في institutional.

## T15 — فهرسة السلسلة والتعافي من الانقطاع (4–6 أيام)

**المالك:** Backend/Data. **Dependencies:** T14 وmanifest T10. **Requirements:** R09,R11.

**Files:** Modify `ai-engine/app/services/blockchain_listener.py`; Create `ai-engine/app/workers/indexer.py`, `ai-engine/app/services/chain_registry.py`, `ai-engine/tests/integration/test_indexer_recovery.py`; تحديث migrations وreadiness.

**Interfaces:** `run_indexer(institution_id,chain_id,contract_version)` يقرأ bounded block ranges؛ key الحدث `(institution_id,chain_id,block_hash,transaction_hash,log_index)`؛ checkpoint يسجل canonical block number/hash؛ حالات observed/confirmed/orphaned؛ تأكيد sandbox=2، وغير sandbox من registry policy لا fallback رقمي عام.

- [ ] اكتب اختبارات event مكرر، crash بين commit/checkpoint، provider rate limit، log removed، chain reorg لعدة blocks، مؤسسة أخرى على الشبكة نفسها، وعقد يطابق العنوان لكن code_hash مختلف.
- [ ] شغّل `python -m pytest -q tests/integration/test_indexer_recovery.py` من ai-engine ضد EVM محلية تدعم snapshot/revert.
- [ ] نفذ commit للevent وcheckpoint في transaction واحدة، backoff محدود، إعادة فحص block hashes وorphaned projection، واشتقاق tenant من registry. لا حذف تاريخ حدث فقد canonical status.
- [ ] تحقق من restart يعيد الفهرس لنفس النتيجة ومن readiness يعرض lag؛ لا استدعاء urllib blocking داخل async handler؛ عامل العملية منفصل مع إيقاف graceful.
- [ ] أضف runbook rebuild من snapshot واختبار مراقبة lag ثم review وcommit.

**القبول:** إعادة المعالجة لا تضاعف المعاملة/التنبيه؛ قرار on-chain نهائي لا يظهر بناء على log orphaned.

## T16 — دورة القضية واعتماد الحل (4–6 أيام)

**المالك:** Backend ثم Frontend مستهلك. **Dependencies:** T13–T15. **Requirements:** R01,R08,R09,R15.

**Files:** Create `ai-engine/app/services/case_service.py`, `ai-engine/app/routes/v2/cases.py`, `ai-engine/app/schemas/cases.py`, `ai-engine/tests/integration/test_case_workflow.py`, `frontend/src/components/CaseWorkspace.jsx`, `frontend/src/components/CaseWorkspace.test.jsx`; Modify `App.jsx`, `Sidebar.jsx` وnavigation labels فقط.

**Interfaces:** `transition_case(identity,case_id,action,expected_version,reason,idempotency_key)->CaseVersion`؛ GET/POST `/api/v2/cases` وGET `/cases/{id}` وPOST `/cases/{id}/transition`؛ جدول state/action/role في التصميم §7 ملزم، بما فيه approve_resolution/reject_resolution/return_to_review. pagination cursor مع ترتيب ثابت `(created_at,id)` وlimit<=100.

- [ ] اكتب table-driven tests لكل انتقال مسموح/مرفوض، REGULATOR write، self-approval، قرارين متزامنين، إصدار قديم409، retry نفس المفتاح يعيد النتيجة نفسها، وتجاوز تحذير EVM لا يغلق القضية تلقائياً.
- [ ] شغّل من ai-engine `python -m pytest -q tests/integration/test_case_workflow.py` قبل implementation؛ استخدم DB حقيقية للتحقق من السباق.
- [ ] نفذ version check وappend-only case_events وقيد SoD، وخيارات تعيين/تصعيد ومراجعة واعتماد بمرجع معاملة وproof. الحقل history غير قابل للتعديل من API.
- [ ] اختبر UI عربية/إنجليزية للحالات الفارغة/الخطأ/الصلاحيات/التزامن، ثم E2E موظف يسلم لمراجع مستقل ويصدر قراراً مع سببه.
- [ ] حدّث OpenAPI/عميل مولد وUAT flow ثم review وcommit.

**القبول:** قضية كاملة قابلة لإعادة بناء تاريخها؛ لا اعتماد ذاتي ولا حالة ضائعة بسبب آخر طلب وصل.

## T17 — إدخال معاملات موثوق وعرض مفهرس (3–5 أيام)

**المالك:** Backend؛ Frontend ينفذ بعد تجميد schema، QA يراجع. **Dependencies:** T14–T16,T06. **Requirements:** R07,R08,R09,R11,R18.

**Files:** Create `ai-engine/app/connectors/csv_import.py`, `ai-engine/app/routes/v2/transactions.py`, `ai-engine/app/schemas/transactions.py`, `ai-engine/tests/integration/test_transaction_import.py`, `shared/fixtures/banking-iqd-demo.csv`; Modify `frontend/src/components/Dashboard.jsx`, `frontend/src/hooks/useAuditEngine.js` لاستهلاك read model المرقم.

**Interfaces:** `POST /api/v2/imports/transactions` stream CSV بأعمدة external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor؛ key `(institution_id,source,external_id)`؛ سجل import id/status/accepted/rejected مع errors لا تحتوي PII. GET `/api/v2/transactions` pagination/filters؛ ETH يأتي من indexer، IQD من connector؛ origin_source محفوظ.

- [ ] اختبر CSV مكرر ومجزأ، صيغة مبالغ/scale/عملة غير صحيحة، timestamp بلا timezone، ملف ضخم، row تالفة، external_id متكرر ببيانات مختلفة، ومؤسسة تتلاعب بمعرف مصدر غيرها.
- [ ] شغّل `python -m pytest -q tests/integration/test_transaction_import.py` ثم نفذ parser متدفقاً وحدود50000row/ملف؛ row conflicts ترفض وتبلغ، ولا يستبدل مصدر قديم صامتاً.
- [ ] اربط dashboard بقراءة صفحات فعلية وفلاتر server-side وإجماليات مفهرسة؛ لا جلب كل txId ثم N استدعاءات لكل refresh؛ مصدر السجل والعملة ظاهران.
- [ ] نفذ E2E استيراد IQD تجريبي ومتابعة EVM منفصلة، restart واستكمال؛ المصدر المصرفي يثبت ورود سجل فقط، ولا يثبت تسوية نقدية أو دقة إدخال العميل.
- [ ] دوّن دليل G2 بجلسات مؤسستين وملف استيراد وقرارات وأدلة ثابتة، ثم review وcommit.

**القبول:** اجتياز G2، وبدء T18 بمصدر مزايا خادمي حقيقي؛ لا تقييم مؤسسي من حقول مخاطر يختارها المتصفح.
