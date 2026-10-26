# Commercial Readiness Implementation Plan — الحزمة الرابعة

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** تحويل المنصة المجربة إلى خدمة تجارية تجريبية يمكن تهيئتها وتشغيلها ودعمها لعدة مؤسسات بأمان.

**Architecture:** تطبيق خلفي مشترك ذو عزل بيانات ومهام، ومجموعة عقود ومفاتيح إثبات وحوكمة مستقلة لكل مؤسسة؛ تهيئة وتعطيل وتصدير قابل للتدقيق. يبدأ النشر المُدار؛ التغليف داخل شبكة العميل مسار لاحق.

**Tech Stack:** البنية المؤسسية نفسها، مع إعدادات عملاء وحصص ومراقبة استخدام ونشر ونسخ احتياطي وسياسات تشغيل؛ لا إدخال منصة خدمات معقدة أو دفع حي لمجرد تسمية المنتج تجارياً.

**Spec:** [التصميم §4–11، R09,R14,R16–R18](../specs/2026-10-22-three-track-development-design.md).

## Global Constraints

- لكل مؤسسة مجموعة العقود الخمسة ومفاتيح حوكمتها الخاصة؛ registry الخادم يختار المجموعة من المؤسسة المصادق عليها. لا صلاحية حوكمة مشتركة بين العملاء.
- G5 يتطلب G4b: تجربة مصرح بها اشتغلت30يوماً مع ملاحظات معالجة وقبول مالك؛ هندسة التجارة يمكن أن تتقدم على مؤسسات اصطناعية.
- لا تحديد SLA أو ادعاء توافر اعتماداً على تخمين؛ قياس30يوماً من البيئة المراقبة أولاً.
- الفواتير الحية وتحصيل المدفوعات والنشر الخارجي والمراسلات تحتاج طلباً مستقلاً؛ هنا تصميم وتشغيل تجريبي واختبارات محلية.

## Review Focus

1. دعم المنصة يحاول رؤية بيانات العميل دون إذن: C01/C05.
2. اسم tenant أو object prefix يأتي من الطلب بدل الهوية: C01/C02.
3. عميل يستهلك CPU/LLM/storage كله ويعطل غيره: C03.
4. ترقية schema ثم rollback قد يعيد تنفيذ outbox أو يفسد snapshot قديمة: C04.
5. مؤسسة جديدة/معطلة/منتهية العلاقة تظل مفاتيحها أو روابط ملفاتها صالحة: C01/C02/C06.

## C01 — دورة حياة المؤسسة وتهيئتها (4–6 أيام)

**المالك:** Backend/Frontend، قائد مالك التكامل. **Dependencies:** G2؛ لا تسليم إطلاق قبل G4b. **Requirements:** R01,R09,R10,R17.

**Files:** Create `ai-engine/app/services/institution_service.py`, `app/routes/v2/institutions.py`, `app/schemas/institutions.py`, `ai-engine/tests/integration/test_institution_lifecycle.py`, `frontend/src/components/InstitutionSetup.jsx`; Modify migrations, chain_registry, AuthProvider.

**Interfaces:** lifecycle DRAFT -> ACTIVE -> SUSPENDED -> CLOSED؛ create/configure/activate/suspend/export requests عبر صلاحية platform_admin بدون حق قراءة محتوى القضايا. المؤسسة ACTIVE بعد تحقق OIDC/registry/storage ووجود4مشاركين مستقلين وحوكمة bootstrap مقفلة؛ setup wizard لا ينشئ مفاتيح الموظفين أو يمسكها.

- [ ] اختبر onboarding مؤسستين، معرف مؤسسة مزور، deployment group لطرف آخر، config غير مكتملة، وتعطيل جلسات/jobs/download grants عند suspend مع حفظ الأدلة.
- [ ] شغّل من ai-engine `python -m pytest -q tests/integration/test_institution_lifecycle.py` قبل implementation ثم طبق انتقالات صريحة وسجل أحداث وRLS.
- [ ] اختبر فصل هوية platform_admin عن AUDITOR؛ support لا يكتسب دوراً بنكياً؛ action إدارة تقنية لا يمنح صلاحية حوكمة عقود العميل.
- [ ] نفذ رحلة إعداد عربية/إنجليزية بتقرير تحقق جاهزية؛ منشئ التسجيل المحلي لا ينشر شبكة عامة تلقائياً.
- [ ] review مستقل للعزل وcommit مستهدف.

**القبول:** يمكن إنشاء/تعليق مؤسسة دون تأثير مؤسسة أخرى أو فقد تاريخ الأولى.

## C02 — عزل المفاتيح والتخزين والتصدير (4–6 أيام)

**المالك:** Backend/DevOps. **Dependencies:** C01,T14,T20,T23. **Requirements:** R09,R14,R17,R18.

**Files:** Create `ai-engine/app/security/secret_provider.py`, `ai-engine/app/services/tenant_export.py`, `ai-engine/tests/integration/test_tenant_keys_and_export.py`, `docs/runbooks/key-rotation.md`, `docs/runbooks/customer-offboarding.md`; Modify evidence_store وLLM config.

**Interfaces:** secret reference لكل institution/usage/version، لا قيمة سرية في DB response أو logs؛ export كامل بقائمة ملفات/قرارات/سياسات/نماذج/anchors وmanifest snapshot؛ download grants أحادية المؤسسة قصيرة العمر<=5min، تتحقق من حالة المؤسسة عند إصدارها واستخدامها عبر proxy مخول.

- [ ] اختبر تبديل key refs بين المؤسسات، تدوير key مع قراءة evidence قديم، رابط ملف بعد تعليق المؤسسة، export بمرفقات ناقصة، ومفتاح مزود AI يظهر في error/log.
- [ ] شغّل `python -m pytest -q tests/integration/test_tenant_keys_and_export.py` ضد secret provider اختباري ومخزن حقيقي؛ لا اختبار بمفاتيح عميل حقيقي.
- [ ] نفذ تغليف/تدوير مفاتيح التشفير مع مسار تحقق واستعادة؛ لا حذف مفاتيح تاريخية قبل اختبار فك البيانات وسياسة احتفاظ مالك المؤسسة.
- [ ] صدّر مؤسسة كاملة واستعدها في instance اختبارية مستقلة وقارن البصمات/القرارات/المراجع؛ إغلاق تجاري لا يمحو حيازة دليل أو legal hold آلياً.
- [ ] وثق المسؤوليات بين مشغل الخدمة ومفاتيح تصويت المؤسسة، ثم review وcommit.

**القبول:** لا سر أو رابط أو artifact من مؤسسة صالح لمؤسسة أخرى؛ offboarding قابل للتدقيق ويحافظ على ما يلزم الاحتفاظ به.

## C03 — حصص واستخدام وعدالة الموارد (3–5 أيام)

**المالك:** Backend/DevOps؛ منتج يحدد الباقات لاحقاً. **Dependencies:** C01,T22. **Requirements:** R09,R16,R17.

**Files:** Create `ai-engine/app/services/quota_service.py`, `app/routes/v2/usage.py`, `ai-engine/tests/integration/test_quotas.py`, `docs/product/service-limits.md`; Modify job queues وimport/export limits.

**Interfaces:** `reserve_usage(institution_id,operation,units,idempotency_key)` و`release/commit` ذريتان؛ GET `/api/v2/usage` للمؤسسة؛ counters للtransactions/storage/exports/LLM tokens. اختبار fixture:100req/min، عمليتا export متزامنتان، ومعالجة file25MB؛ هذه حدود تجربة لا تسعير متفق عليه.

- [ ] اختبر طلبين متزامنين قرب السقف، retry لا يحتسب مرتين، job فاشلة تحرر الحجز، admin لا يعطل audit log، ومؤسسة مرهقة لا تجوّع غيرها.
- [ ] شغّل `python -m pytest -q tests/integration/test_quotas.py` ثم طبق counters ذرية وqueue fairness و429 مع Retry-After؛ لا عدادات local process فقط.
- [ ] نفذ حمل مؤسستين، واحدة تتجاوز حصتها؛ الثانية تحافظ على أهداف T22؛ حد cloud cost لكل مؤسسة دون طلب provider حي غير مصرح.
- [ ] صمم سجل استخدام يمكن مراجعته وتصديره؛ pricing/billing الحي مؤجل؛ لا عدادات PII أو source code خام في telemetry.
- [ ] review وcommit، وأضف resource alert مبني على الاستهلاك الفعلي.

## C04 — إصدارات وانتقال وتراجع آمن (4–6 أيام)

**المالك:** DevOps/Backend/Web3 بمالك تكامل واحد. **Dependencies:** C01,C02,T23. **Requirements:** R08,R16,R18.

**Files:** Create `docs/runbooks/release-and-rollback.md`, `ops/release/verify.ps1`, `tests/e2e/upgrade-compatibility.spec.js`, `docs/product/version-support.md`; Modify migration/deployment validation وCI.

**Interfaces:** release manifest {app_version,api_schema_hash,db_migration_head,contracts_version,supported_legacy_versions,model_registry,build_digest}؛ migrate expand/contract؛ القديم والجديد يعملان خلال نافذة التحديث المقترحة، ولا rollback يخفض DB بشكل مدمر.

- [ ] اختبر V2 case/export قديمة بعد ترقية التطبيق، outbox قيد المعالجة، فشل migration جزئياً، عناوين عقود مختلطة، وrollback التطبيق قبل إنهاء contract migration.
- [ ] شغّل `npm run test:integration -- --grep upgrade` بعد إضافة script/سيناريو معلنين؛ استخدم مؤسسات اختبار ونسخ backup مختبرة، لا شبكة عميل.
- [ ] نفذ preflight يمنع تفعيل إصدار بعقد/schema غير مدعوم، migration سجلها غير مطابق أو secrets مفقودة؛ لا استبدال تاريخ عقود immutable.
- [ ] أثبت rollback التطبيق مع الحفاظ على كل القرارات والطلبات؛ عند عدم التوافق ينتقل read-only مع سبب وخطة استعادة بدلاً من إتلاف البيانات.
- [ ] review وتعريف مصفوفة دعم الإصدارات ثم commit.

## C05 — تشغيل ودعم وتوثيق منتج (3–5 أيام + فترة قياس)

**المالك:** DevOps/منتج/كاتب تقني من الفريق. **Dependencies:** T23,T25,C01–C04. **Requirements:** R15,R16,R17.

**Files:** Create `docs/product/admin-guide-ar.md`, `user-guide-ar.md`, `user-guide-en.md`, `support-policy.md`, `service-level-measurement.md`, `docs/runbooks/support-access.md`; Modify monitoring dashboards وrunbooks.

**Interfaces:** كل incident تقني request_id/time/tenant opaque ref/severity/owner/updates؛ support access مؤقت ومحدد بموافقة مسؤول المؤسسة وسبب audit event، دون صلاحية تصويت مالي. مؤشرات availability/error/latency/bakup_age/index_lag مع تعريف واضح لفترة القياس.

- [ ] اختبر دخول دعم غير مخول وموافقته المؤقتة وانتهائها؛ لا تنزيل أدلة أو ظهور بيانات مؤسسة افتراضياً؛ كل قراءة دعم مخولة تسجل.
- [ ] شغّل تجربة tabletop لتوقفDB، فقد writer key، تعطّل LLM، وإيقاف مؤسسة؛ صِف الخطوة والمسؤول وزمن الاستجابة المقاس.
- [ ] قس التوافر30يوماً منذ بدء تشغيل البيئة المراقبة؛ اكتب مستوى الخدمة المقترح بعد النتائج، مع الاستثناءات وحدود ساعات الدعم، لا وعد99.9% بلا دليل.
- [ ] راجع الأدلة الإرشادية مع operator/auditor/regulator من اختبار UAT؛ أزل كل ادعاء قانوني/تسويقي غير مؤيد بمرجع واعتماد مالكه.
- [ ] سجل عروض دعم/تكلفة تشغيل تقديرية ذات مدخلات معلنة لا أسعار مختلقة، ثم review وcommit الوثائق.

## C06 — تشغيل التجربة وقبول النسخة التجارية (نافذة تشغيل30يوماً + مراجعة)

**المالك:** مالك المنتج والجهة التجريبية ومسؤول التشغيل ومراجع مستقل. **Dependencies:** G4 لبداية التجربة، C01–C05 لـG5. **Requirements:** R13,R16,R17.

**Files:** Create `docs/uat/pilot-exit.md`, `docs/product/commercial-beta-checklist.md`, `docs/product/decision-log.md`, `docs/verification/commercial-readiness.md`.

**Interfaces:** pilot registry يوثق المؤسسة/إذن البيانات/users/scope/start/end/monitoring/feedback/issues/acceptance؛ إصدار beta يحمل نطاقاً معروفاً ومخاطر وحدود استخدام؛ لا اقتراح إطلاق عام ضمن الطلب التخطيطي.

- [ ] ابدأ تجربة بعد G4 واعتماد مالك البيانات ودورة المستخدمين، وسجل بداية30يوماً. إن لم تتوفر مؤسسة، شغّل بيئة اصطناعية للتطوير واترك G4b غير مكتملة.
- [ ] اجمع نجاح المهام، وقت التحقيق والإنذارات الكاذبة وحوادث التشغيل وتكاليف الموارد، مع baseline ومقارنة؛ لا تساوِ عدم وجود شكاوى بانعدام المشاكل.
- [ ] عالج findings واعتمد نتيجة G4b من مالك التجربة؛ المراجعة المستقلة تعيد اختبارات العزل/الترقية/استعادة البيانات والتقرير الموقع.
- [ ] تحقق من G5: دورة عميل ومفاتيح/حصص/تصدير/دعم، قياس30يوماً، نموذج تسعير مقترح ودراسة تكلفة يراجعها مالك المنتج، ومراجعة شروط الخدمة/الخصوصية لدى الجهة المختصة قبل طرح حقيقي.
- [ ] سلّم ثلاث حزم: A بحث ونتائج، I تجربة ونتائج تشغيل، C beta جاهزة للمراجعة؛ دوّن ما بقي بدقة، ثم commit الوثائق. النشر أو التعاقد أو إرسال مراسلات خطوة منفصلة بطلب المستخدم.

**القبول:** لا يوصف النظام بأنه جاهز تجارياً لأن build/tests نجحت فقط؛ جاهزيته مقيدة بنجاح تجربة فعلية وأدلة تشغيل ومراجعة ونطاق خدمة معروف.
