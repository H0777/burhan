# Research and Pilot Implementation Plan — الحزمة الثالثة

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** إثبات نتائج بحثية قابلة للتكرار، وتقييم مالي موثق، وتجهيز تجربة مؤسسية بقياسات أداء واستعادة وأمان فعلية.

**Architecture:** تقييم خلفي من بيانات مفهرسة، محرك قواعد baseline ونموذج اختياري، تقرير حتمي يستند إلى ملفات ومرساة موثوقة؛ LLM مساعد اختياري منفصل عن التحقق والاعتماد.

**Tech Stack:** Python/scikit-learn، PostgreSQL read models، العقود وAPI V2، React، أدوات حمل واختبار E2E؛ dependencies تقفل عند التنفيذ.

**Spec:** [التصميم §6–10، R04,R07,R12–R16](../specs/2026-10-22-three-track-development-design.md).

## Global Constraints

- لا هدف دقة تسويقي مفترض؛ النموذج يفعّل افتراضياً فقط إذا حقق recall لا يقل عن baseline وfalse positives أقل على الاختبار المحجوز، وإلا تبقى القواعد الافتراضية ويُوثق فشل الفرضية.
- لا إرسال للأدلة إلى نموذج سحابي افتراضياً؛ التنقيح والتفعيل لكل مؤسسة.
- الأموال الدقيقة تبقى int/Decimal؛ float للمزايا الإحصائية المشتقة المحدودة فقط.
- مدة16أسبوع هدف جاهزية التجربة؛ نجاح تشغيلها الفعلي بوابة G4b منفصلة بعد30يوماً على بيئة مراقبة.

## Review Focus

1. عميل/موظف من التدريب يتسرب للاختبار أو labels مشتقة من القاعدة نفسها: A01/T19.
2. تبديل السياسة/حدود منتصف الليل/إعادة تقييم سجل قديم: T18 يحفظ الإصدار والوقت والمزايا.
3. إضافة دليل بعد تقرير صادر أو انقطاع RPC: T20 يحفظ snapshot وstatus بلا تضليل.
4. LLM يهلوس اعتماداً أو يتلقى prompt injection في دليل: T21 يمنع تغيير الحقائق/الأذونات.
5. نسخ احتياطي دون مفاتيح/كائنات أو restore يكرر outbox: T23.

## A01 — بروتوكول البحث ومصفوفة التهديد (يبدأ الأسبوع1؛ 2–3 أيام ثم متابعة)

**المالك:** باحث/Backend مع قائد تقني. **Dependencies:** baseline T01؛ لا ينتظر G2 لكتابة البروتوكول. **Requirements:** R13,R15.

**Files:** Create `research/protocol.md`, `research/dataset-card.md`, `research/experiment-manifest.schema.json`, `research/requirements-matrix.csv`; Modify `docs/threat-model.md` لتفريق implemented/planned/unsupported.

**Interfaces:** manifest {dataset_hash,split_hash,code_revision,config_hash,seed,policy_version,engine_version,model_hash,metrics,environment}؛ hypotheses عن أثر الحوكمة على replay والانتحال، وأثر ML على baseline، وكلفة الإثبات والتوسع.

- [x] حدد التجارب قبل النتائج: rules-only، ML-only، hybrid؛ fault injection للهوية/replay/evidence tamper؛ لا مساواة anomaly بجريمة مثبتة.
- [x] حدد فصل الزمن والعميل والمؤسسة، وقائمة labels مستقلة ومصدرها، ومقاييس precision/recall/F1/PR-AUC/FP-per1000/p95؛ دوّن حدود الاختبار الاصطناعي.
- [x] أضف تدقيق بروتوكول: لا overlap بين subject_ids، ولا tuning على holdout، وبذور42/43/44 للبيانات الاصطناعية؛ ملفات الاختبار تتولد وتُحفظ بصمتها قبل training.
- [x] راجع التهديدات مقابل اختبارات T02/T03/T05/T14؛ الادعاء غير المثبت يحمل planned أو limitation.
- [x] احفظ الوثائق بعد مراجعة أكاديمية؛ لا نشر بحث أو بيانات تلقائي.

**القبول:** يستطيع باحث آخر معرفة كيف يرفض الفرضية وما البيانات التي تدعم الاستنتاج؛ لا ترجع لتغيير البروتوكول لإخفاء نتيجة سلبية.

## T18 — مزايا مخاطر موثوقة وسياسات زمنية (3–5 أيام)

**المالك:** Backend/Data. **Dependencies:** G2,T06,A01. **Requirements:** R07,R12.

**Files:** Create `ai-engine/app/services/feature_service.py`, `assessment_service.py`, `ai-engine/app/schemas/assessment.py`, `ai-engine/app/routes/v2/risk.py`, `ai-engine/tests/integration/test_authoritative_scoring.py`; Modify `app/models/fraud_detector.py`, `insider_analyzer.py`, `frontend/src/components/RiskScorePanel.jsx`, `InsiderMonitor.jsx` بعد schema freeze.

**Interfaces:** `build_features(identity,transaction_id,as_of,policy_version)->FeatureSnapshot`؛ `assess_transaction(...)->Assessment` حسب التصميم §7؛ preview endpoint يعيد source=simulation ولا يحفظ قراراً؛ score/level/factors/engine/model_loaded/policy_version/features_hash محفوظة مع الزمن.

- [x] اختبر محاولة تمرير kyc_verified/override_count/threshold من العميل في assess؛ ترفض الحقول أو يتجاهل المصدر غير الموثوق برفض صريح؛ اختبر مبلغ فوق2^53 ونوافذ10min/24h و23:59/00:01 في بغداد وتغيير السياسة بعد الواقعة.
- [x] شغّل من ai-engine `python -m pytest -q tests/integration/test_authoritative_scoring.py` ثم نفذ aggregation عبر tenant/time indexes؛ derive features من سجل السلطة لا من query body.
- [x] احفظ snapshot للقواعد النشطة عند القرار؛ إعادة التقييم تنشئ assessment جديداً وتحافظ على الأصلي؛ severity/recommendation لا تستبدل قرار المحقق.
- [x] اختبر UI يعرض assessment المصدر والإصدار والأسباب الفعلية؛ explainability لا تكون أوزاناً ثابتة مختلقة؛ حال فقد مصدر يعلن unavailable.
- [x] حدّث schema/عميل واختبارات legacy demo مع تسمية واضحة ثم review وcommit.

**القبول:** بيانات قديمة تعاد بنتيجتها الأصلية؛ محاولات تخفيض المخاطر من المتصفح لا تغير التقييم المؤسسي.

## T19 — تدريب وتقييم قابلان للتكرار (4–7 أيام)

**المالك:** Data/باحث. **Dependencies:** T18,A01؛ بيانات مصرح بها أو اصطناعية معلنة. **Requirements:** R12,R13.

**Files:** Modify `ai-engine/app/models/trainer.py`, `ai-engine/app/models/fraud_detector.py`, `ai-engine/app/config.py`, `scripts/generate_dataset.js`; Create `research/protocol.json`, `research/run_experiments.py`, `research/evaluate.py`, `research/results/README.md`, `ai-engine/tests/test_model_registry.py`, `research/tests/test_splits.py`.

**Interfaces:** `ModelArtifact{model_hash,feature_schema,training_dataset_hash,library_versions,created_at,metrics}`؛ `load_validated_model(path,expected_hash)->ModelStatus`؛ لا قبول pickle مرفوع من مستخدم، ولا marker نصي باسم model ناجح. سجلات loading صريحة وreadiness تعكس الحقيقة.

- [x] اختبر split leakage، artifact مفقود/معدل، feature order غير مطابق، اختلاف نسخة مكتبة، ونموذج يفشل مع baseline؛ لا تسقط الأخطاء في pass صامت.
- [x] شغّل `python -m pytest -q tests/test_model_registry.py` من ai-engine و`python -m pytest -q research/tests/test_splits.py` من الجذر بعد تهيئة import paths الموثقة.
- [x] طبق train/evaluate وmanifest A01 وإزالة generator الذي يكتب placeholder كنموذج؛ artifact موثوق للقراءة فقط، مع pin اعتماديات وتحقيق hash قبل joblib.load.
- [x] شغّل من الجذر `python research/run_experiments.py --config research/protocol.json` بعد إنشاء config المكافئ للبروتوكول؛ سجّل النتائج الفعلية للنسخ الثلاث؛ نفس manifests تعطي نفس splits ونتائج ضمن tolerance مكتوبة1e-6 عند البيئة المقفلة.
- [x] اكتب model/dataset cards والقيود وقرار التفعيل؛ راجع وcommit الملفات النصية والملخصات، والبيانات الحساسة لا تدخل Git.

**القبول:** لا claim بتحميل/دقة ML دون artifact صالح وتقييم؛ النتيجة السلبية مخرج بحثي مقبول وتبقى القواعد فعالة.

## T20 — تقرير وإيصال قابلان للتحقق (3–5 أيام)

**المالك:** Backend؛ Frontend للمظهر والتصدير بعد تثبيت API. **Dependencies:** T05,T14,T16,T18. **Requirements:** R04,R05,R12,R15,R18.

**Files:** Create `ai-engine/app/services/report_service.py`, `evidence_export.py`, `ai-engine/app/routes/v2/reports.py`, `ai-engine/tests/integration/test_report_provenance.py`, `scripts/verify-evidence-export.py`; Modify `frontend/src/components/ForensicReport.jsx`, `ForensicExplorer.jsx`, `frontend/src/utils/merkle.js`.

**Interfaces:** POST `/api/v2/cases/{id}/reports` حسب التصميم؛ export zip يحتوي manifest موقع، evidence hashes/object versions، schema version، snapshot block_number/hash وcount/head، assessments/decisions بدون أسرار. `verify-evidence-export.py --bundle path --registry path` يتحقق مستقلاً ويرجع status وأسباب؛ dossier_hash يلتزم بالmanifest والمحتوى الكامل لا عدد الأدلة والعنوان فقط.

- [ ] اختبر تغيير بايت في الملف، نص التقرير، منفذ القرار، توقيع manifest، root محلي مصطنع، export تابع لمؤسسة أخرى، legacy محدود المصدر، وRPC غير متاح؛ كل حالة تحمل status/provenance الصحيح.
- [ ] شغّل `python -m pytest -q tests/integration/test_report_provenance.py` من ai-engine قبل implementation.
- [ ] نفذ تقريراً حتمياً يفصل observation/allegation/assessment/human decision؛ أزل الأختام/الاعتماد الرسمي الثابت والاتهامات التجريبية من institutional؛ احفظ إصدار التقرير ولا تستبدله.
- [ ] تحقق من export ثم أضف دليلاً جديداً: يبقى snapshot التقرير القديم صالحاً؛ تحقق من نص عربي/إنجليزي طويل وطباعة سليمة وبصمات كاملة قابلة للنسخ؛ لا ترابط hash فقط دون file verification.
- [ ] سجل حالة legacy_unrestricted_submission بشكل ظاهر ووقع manifest بمفتاح صادر للمؤسسة مع public-key registry؛ review وcommit.

**القبول:** طرف مستقل يستطيع التحقق من سلامة النسخة المصدرة ومرجعها دون الاعتماد على لون زر في الواجهة؛ انقطاع المصدر ينتج unavailable.

## T21 — فحص عقود صادق وLLM اختياري (2–4 أيام)

**المالك:** Backend/Data. **Dependencies:** T07,T13,T18,T20. **Requirements:** R12,R14,R15.

**Files:** Modify `ai-engine/app/services/gemini_service.py`, `app/routes/contract_scanner.py`, `frontend/src/components/ContractScanner.jsx`; Create `ai-engine/app/services/llm_provider.py`, `scanner_service.py`, `ai-engine/tests/test_scanner_modes.py`, `test_llm_privacy.py`؛ routes/v2/scanner.py للنقاط الجديدة.

**Interfaces:** `scan(code,mode='patterns')->ScanResult{engine,coverage,findings,limitations}`؛ `generate_narrative(redacted_context,provider_config)->NarrativeResult` دون integrity flag؛ provider/model configurable بقائمة تم التحقق من دعمها عند التنفيذ، API key لكل مؤسسة لا في URL logs.

- [ ] اختبر تعليقاً يحتوي tx.origin، كوداً طويلاً فوق200KB، نمطاً غير مدعوم، provider404/timeout، JSON مخالف، instruction داخل دليل، وتفعيل cloud لمؤسسة لا يفعلها لأخرى.
- [ ] شغّل من ai-engine `python -m pytest -q tests/test_scanner_modes.py tests/test_llm_privacy.py` ثم نفذ timeout/size limits وتنقيحاً وopt-in؛ patterns لا يُسمى AST أو تدقيقاً أمنياً معتمداً.
- [ ] أي AST mode فعلي يضيف parser/scanner مثبت الإصدار بعملية مقيدة ولا ينفذ code المرفوع؛ غيابه يعيد unsupported ولا secure.
- [ ] أثبت باختبار أن LLM لا يغير status الدليل/صلاحيات/قرار مالي، وأن السياق المرسل منقح ومسجل metadata دون محتوى حساس.
- [ ] راجع labels والوصف وحدّث مسودة البحث بالقدرات الحقيقية ثم commit.

**القبول:** G3/A بدليل تجارب وتقارير ومحركات معلنة؛ external cloud test اختياري بإذن الجهة المالكة، لا API call حقيقي مطلوب لاختبار الخصوصية الأساسي.

## T22 — قياس وتحسين الأداء المحدد (2–4 أيام)

**المالك:** QA/DevOps مع صاحب bottleneck. **Dependencies:** G2,T18,T20. **Requirements:** R11,R16.

**Files:** Create `tests/load/scenarios.js`, `tests/load/seed_reference.py`, `docs/verification/performance.md`; Modify استعلامات/read model وfrontend dynamic imports عند إثبات الحاجة؛ لا ضبط release profile بلا قياس.

**Interfaces:** script `test:load` يوثق الأداة/الإصدار والهاردوير/dataset/rate؛ GET pages limit<=100؛ DB indexes تراجع بخطط query مقاسة؛ frontend lazy-load للمكونات الثقيلة.

- [ ] جهز100ألف معاملة و10آلاف قضية في مؤسسة اختبار، و100مستخدم افتراضي و10req/s لمدة30دقيقة على4vCPU/8GB؛ سجل baseline وp50/p95/error/CPU/memory/lag.
- [ ] اختبر أن الحمل يشمل authenticated reads وassess وexport queue بحدود معلنة؛ لا تقارن LLM أو زمن السلسلة بزمن API المحلي.
- [ ] عالج أكبر bottleneck مثبت، وأعد السيناريو نفسه؛ أهداف p95<=500ms للقوائم و<=300ms للقواعد وأخطاء<1%، أو سجل الفرق وأثره ولا تدّع النجاح.
- [ ] قارن bundle والتحميل قبل/بعد التقسيم؛ لا هدف حجم عشوائي يحل محل قياس الاستخدام العربي الطويل.
- [ ] سجل الأجهزة والنتائج والمحددات ومخرجات الأداة ثم review وcommit.

## T23 — الاستعادة والانتقال والمراقبة (3–5 أيام)

**المالك:** DevOps/Backend. **Dependencies:** T14,T15,T20,T22. **Requirements:** R11,R16,R18.

**Files:** Create `ops/backup.ps1`, `ops/restore.ps1`, `ops/health/`, `docs/runbooks/recovery.md`, `docs/runbooks/incident-response.md`, `docs/verification/recovery-drill.md`; تحديث readiness ومقاييس request errors/queue age/index lag/storage/model status.

**Interfaces:** backup manifest يربط DB snapshot وobject versions وkey references وchain registry/cutoff؛ secrets لا تدخل Git؛ restore يدعم instance جديدة isolated، ويعيد outbox/checkpoints بصورة idempotent.

- [ ] نفذ backup ثم crash مخطط داخل بيئة اختبار؛ احذف نسخة الاختبار فقط بعد فحص المسارات والأسماء، واستعد إلى instance مختلفة؛ لا تلمس خدمات المستخدم القائمة.
- [ ] تحقق من عدّ القضايا والقرارات وبصمات الملفات وسلامة snapshot تقارير قبل/بعد، ومن عدم تكرار الطلبات المالية/anchor عند استئناف العامل.
- [ ] قس RPO<=15min وRTO<=2h فعلياً؛ فشل فقد key أو missing object يمنع جاهزية زائفة ويظهر إجراء استرداد موثقاً.
- [ ] اختبر تدوير محفظة حوكمة مفقودة باستخدام4مشاركين وغياب1 بلا تجاوز قاعدة proposer+2approvers؛ لا توصف قراءة legacy بأنها أصل موثوق تلقائياً.
- [ ] أرفق نتائج وتنبيهات وتجربة rollback تطبيق دون مسح تاريخ، ثم review وcommit.

## T24 — مراجعة مستقلة وإغلاق المخاطر (3–5 أيام + زمن الإصلاح)

**المالك:** مراجع أمني مستقل عن التنفيذ؛ الإصلاحات عند أصحاب الوحدات. **Dependencies:** T01–T23. **Requirements:** R01–R18 ذات الصلة بالتجربة.

**Files:** Create `docs/security/pilot-review.md`, `docs/security/risk-register.md`؛ tests regression عند كل finding في مساره المالك، لا تغييرات كود بلا تعيين ملكية.

**Interfaces:** سجل المراجعة `{finding_id,requirement_id,severity,evidence,owner,status,regression_test,verification_result,accepted_by}`؛ الحالات OPEN/IN_REMEDIATION/VERIFIED_FIXED/ACCEPTED_RISK. G4 يستهلك هذا السجل، ولا يقبل ACCEPTED_RISK لانتحال أو كسر عزل أو تحقق كاذب.

- [ ] راجع final diff والعقود المنشورة محلياً وAPI/RLS/storage/keys/export ضد نموذج التهديد؛ الصلاحية تطبق عند الخادم والعقد لا الواجهة وحدها.
- [ ] أعد تجارب الانتحال/replay/zero timelock/cross-tenant/snapshot truncation/LLM leakage بمصادر حقيقية أو توثيق نوع mock بدقة.
- [ ] لكل finding: severity، مسار وإثبات، مالك، اختبار رفض قبل الإصلاح، ثم تحقق مستقل بعد الإصلاح.
- [ ] يمنع G4 بCritical/High مفتوح يتعلق بالثقة/الصلاحيات/الأدلة؛ بقية المخاطر لها قبول مالك موثق، لا صمت أو suppress.
- [ ] سلّم تقريراً منفصلاً عن تقرير المنفذ مع الأوامر التي شغلت والاختبارات التي لم تشغل، ثم commit وثائق فقط عند المراجع.

## T25 — قبول التجربة والحزمة الأكاديمية (3–5 أيام)

**المالك:** منتج/امتثال وباحث وQA. **Dependencies:** A01,T19–T24. **Requirements:** R13,R15,R16.

**Files:** Create `docs/uat/pilot-scenarios.md`, `docs/uat/pilot-readiness.md`, `research/paper-outline.md`, `research/reproducibility.md`, `docs/runbooks/pilot-start.md`; Modify README/docs القديمة لإزالة claims غير المثبتة.

**Interfaces:** UAT سبع رحلات: تسجيل دخول، إدخال معاملة، مراجعة تنبيه، فصل واجبات، موافقات، تحقق وتصدير، استعادة/تعطل؛ لكل رحلة actor/data/steps/expected/actual/evidence/signoff.

- [ ] نفذ الرحلات بالعربية والإنجليزية مع operator/auditor/regulator/admin ومؤسستين؛ اختبر لوحة مفاتيح وحالات خطأ ونصوص طويلة.
- [ ] أعد التجارب الأكاديمية من نسخة/بيئة نظيفة على artifact manifest محفوظ؛ اكتب النتائج المقاسة والقيود والمقارنات، دون ادعاء اعتماد أو تعميم بلا بيانات.
- [ ] حدّد مالك بيانات ومسؤول تشغيل ومدة30يوماً ومقاييس نجاح ومصدر معاملات للتجربة؛ عند عدم توفر مؤسسة تبدأ تجربة اصطناعية معلنة ولا تُحسب G4b.
- [ ] سلّم G4 readiness مع قائمة ما نفذ/ما قُبل/ما أُجل؛ لا تُعلّم G4b مكتملة قبل تجربة تشغيل فعلية.
- [ ] review وcommit، وتسليم حزمة أكاديمية جاهزة للمراجعة؛ النشر الخارجي ليس جزءاً من المهمة.

**القبول:** بحث قابل لإعادة نتائجه وG4 موثقة؛ بدء تجربة فعلية مشروط ببيانات ومستخدمين وإذن الجهة المالكة، ويسجل في C06.
