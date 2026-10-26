# إصلاح البحث والقبول والتسليم — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** نتائج بحث صادقة واختبارات تشغيل قابلة للإعادة وإغلاق مخاطر يستند إلى نسخة نهائية مختبرة.

**Architecture:** فصل بوابة البحث عن بوابة التشغيل، ثم تمرير رحلة مؤسسية فعلية وحمل واستعادة ومراجعة مستقلة قبل التسليم. الفشل البحثي يبقي ML معطلاً، ولا يبرر اختلاق نجاح أو إخفاء نتيجة سلبية.

**Tech Stack:** Python/scikit-learn/pytest، PostgreSQL 16، HTTP load runner، Playwright، Hardhat، GitHub Actions.

**Spec:** [§9–10 من التصميم](../specs/2026-10-23-verified-remediation-design.md).

## Global Constraints

- recall_test>=0.85 وFPR<=50 لكل ألف وPR-AUC>=0.80 وscoring p95<=25ms كما في protocol الحالي؛ تفعيل ML يتطلب أيضاً recall>=baseline وFPR<=baseline وتحسناً صارماً في واحد منهما.
- train/validation/test زمنية ومفصولة بالمشارك؛ لا أقل من 100 عينة أو غياب فئة في أي split؛ لا تعديل threshold بعد اختبار test.
- حمل: 100,000 معاملة و100 مستخدم و30 دقيقة بعد warm-up=5 دقائق؛ p95 read<=500ms، transition<=1s، قبول ملف1MiB<=2s، و5xx<1%.
- لا نجاح RG1–RG4 دون أدلة بناء نهائي؛ التجربة المؤسسية اللاحقة 30 يوماً منفصلة.
- المصادر والـlockfiles وتعديلات المستخدم تُحفظ؛ لا نشر خارجي أو نقل بيانات حقيقية ضمن إعداد الخطة.

## Review Focus

1. sender يظهر في التدريب والاختبار بأزمنة مختلفة — R17 يزيل التسرب ولا يعوضه بنقل المستقبل للماضي.
2. كل scores متساوية أو لا توجد فئة إيجابية — R18 يرفض المقياس غير المعرف أو يحسب ties بثبات.
3. نقطة توقف عامل أو RPC أثناء الحمل — R19/R20 يثبتان عدم تحويل الفشل إلى verified.
4. نجاح mocks مع فشل رحلة HTTP الحقيقية — R20 يتطلب خدمات ومصادقة وعقوداً فعلية.
5. الرجوع إلى إصدار قديم يعيد bypass — R21 يجعل الرجوع read-only ويصالح المعاملات المبثوثة.

## R17 — فصل بحث زمني وهوية وبصمات كاملة

**الاعتماد:** R00. **المالك:** البحث؛ لا يتطلب انتظار حزم التشغيل.

**الملفات:** تعديل research/run_experiments.py وresearch/protocol.json وresearch/tests/test_splits.py وresearch/experiment-manifest.schema.json. إنشاء research/tests/test_leakage.py وresearch/schemas/split-manifest.schema.json. تحديث research/requirements-matrix.csv لربط المطالب بالاختبارات دون إعلان نجاح مسبق. protocol.json يبقى مصدر الإعداد الواحد وتضاف إليه cutoffs وسياسة التفعيل؛ لا config موازٍ بحدود مختلفة.

**الواجهات:**

    partition_splits(records:list[dict],train_end:datetime,
                     validation_end:datetime) -> SplitManifest
    validate_splits(manifest:SplitManifest,records:list[dict]) -> None

SplitManifest يحفظ جميع record IDs في كل split، وparticipant IDs، وcutoffs UTC، وseed، وdrop reasons/counts، وبصمة SHA-256 للمصدر ولكل قائمة مرتبة كاملة. لا تكتفِ بأول50 معرفاً. cutoffs تُحفظ في config قبل التدريب ولا تستنتج من label أو جودة النتيجة.

سياسة الفصل المحددة: train=records<=train_end. validation يحتفظ فقط بمشاركين first_seen>train_end وlast_seen<=validation_end وبسجلاتهم في النافذة. test يحتفظ فقط بمشاركين first_seen>validation_end وسجلاتهم اللاحقة. تُسقط السجلات اللاحقة لمشاركي train؛ ومن يعبر validation/test لا يدخل أياً من مجموعتي التقييم. يُسجل سبب كل إسقاط. كل feature تاريخي لا يرى أحداثاً بعد زمن السجل، وfit التحويلات على train فقط.

- [ ] أضف temporal_order_and_actor_disjoint بمجموعات تحتوي عمداً على مشارك عابر؛ asserts: max(train.time)<min(validation.time)، max(validation.time)<min(test.time)، وتقاطع actor sets فارغ في الأزواج الثلاثة.
- [ ] أضف no_future_record_for_training وfull_manifest_hash_changes_if_record_51_changes وscaler_fit_uses_train_only وfeature_history_cannot_read_future. أضف empty_or_too_small_or_single_class_split_fails؛ لا fallback إلى random split.
- [ ] شغل node scripts/run-python.js -m pytest -q research/tests/test_splits.py research/tests/test_leakage.py؛ سجّل فشل الفصل الحالي الذي يعتمد sender sorting.
- [ ] نفذ الواجهات والسياسة؛ لكل source ID إما split واحد أو سبب إسقاط صريح. لا تولد dataset جديداً ثم تدّعي أنه يمثل بيانات مؤسسة حقيقية؛ يبقى synthetic موصوفاً كما هو.
- [ ] حدّث config/manifest/schema، وسجل actual Python/NumPy/scikit-learn/runtime versions وبصمة artifact ومصدر المعرفات. لا hardcoded sklearn version، ولا pickle غير موثوق دون hash مسجل.
- [ ] شغل الاختبارات، ثم تجربة بحث قصيرة من config مثبت إلى مجلد run جديد؛ إذا أدى الفصل السليم إلى بيانات غير كافية فالنتيجة INSUFFICIENT_DATA لا SUPPORTED.
- [ ] سجل R17.md وراجع الفرق وcommit محصوراً. لا تستبدل النتائج السابقة بلا سجل version أو تعيد استعمال test للتوليف.

## R18 — مقاييس محسوبة وقرار تفعيل قابل للفشل

**الاعتماد:** R17. **المالك:** البحث؛ تعديل config/runtime عند مالك التشغيل.

**الملفات:** تعديل research/run_experiments.py وresearch/protocol.json وresearch/results/README.md وai-engine/app/models/registry.py وservices/assessment_service.py. إنشاء research/tests/test_evaluation_gate.py وtest_metrics.py وai-engine/tests/integration/test_model_activation_gate.py. تحديث ai-engine/tests/test_model_registry.py وresearch/experiment-manifest.schema.json.

**الواجهات:**

    evaluate_gate(metrics:EvaluationMetrics,baseline:EvaluationMetrics,
                  policy:EvaluationPolicy) -> GateDecision
    GateDecision(research_status,activation_allowed:bool,reasons:list[str])
    ModelRegistry.activate(model_id:str,run_manifest_path:Path) -> None

الحالات البحثية PASSED، FAILED، INSUFFICIENT_DATA؛ CLI --check-gate exit0 للنجاح و1 للفشل و2 للبيانات/البيئة غير الكافية. نص الادعاء يولد من القرار ولا يكون string ثابت SUPPORTED. activation_allowed يتطلب بصمات split/model/policy وأن يطابق model artifact الذي سيحمله الخادم.

- [ ] أضف observed_metrics_fail_activation بقيم recall=0.7698 وFPR=0.00157 وbaseline_fpr=0، وrecall_085_same_fpr_with_recall_gain_passes عندما baseline recall أقل وباقي حدود protocol ناجحة، وsame_metrics_no_strict_gain_blocks_activation، وfpr_decrease_with_recall_drop_blocks_activation. اختبر أن FPR العرض1.57 لكل ألف يساوي0.157%، وPR-AUC=0.79 أوp95=25.01ms يفشلان gate.
- [ ] أضف metric_zero_denominator_not_zero_success وties_permutation_invariant وall_scores_equal وknown_confusion_matrix. وضح precision/recall/FPR وPR-AUC/AP بالاسم المحسوب؛ لا تعرض AP باسم مقياس آخر. عند غياب فئة ارفض gate بدلاً من قسمة صامتة.
- [ ] أضف invalid_manifest_or_hash_blocks_activation وfailed_gate_keeps_rule_based وtest_threshold_cannot_be_retuned_after_seal. seal يحفظ hash labels/predictions/config ووقت التقييم؛ أي إعادة فتح تتحول إلى run جديد ولا تعد اختباراً مستقلاً على dataset سبق رؤيتها.
- [ ] شغل node scripts/run-python.js -m pytest -q research/tests/test_evaluation_gate.py research/tests/test_metrics.py ai-engine/tests/integration/test_model_activation_gate.py.
- [ ] نفذ حساب المقاييس وتجميع score ties باستخدام مكتبة المشروع أو خوارزمية مثبّتة باختبار، وأخرج confusion matrices وconfidence intervals95% وحجم العينات وحدود synthetic. لا تخفض0.85 أو تسمح FPR أسوأ لإغلاق مهمة.
- [ ] أزل SUPPORTED والتفعيل hardcoded، واربط سجل النموذج بقرار التقييم؛ default rule_based، وإذا طلب المشغل hybrid مع نموذج غير مجاز يفشل البدء أو الطلب بوضوح وفق مسار الإعداد، ولا fallback غير معلن.
- [ ] أعد التجربة وفق CLI الحالي مع إضافة --config research/experiment-config.json و--check-gate؛ يجب أن تفشل النتائج الحالية إن بقيت كما هي. شغل الاختبارات وtest_model_registry.py، وسجل R18.md والقرار البحثي كما خرج، ثم commit محصوراً.

## R19 — حمل خارجي وقياس تأخير الفهرسة والتثبيت

**الاعتماد:** R09، R12، R14، R15. **المالك:** QA/الأداء.

**الملفات:** تعديل tests/load/scenarios.py وscenarios.js وseed_reference.py وdocs/verification/performance.md. إنشاء tests/load/profile.json وtests/load/test_profile.py وops/collect-metrics.ps1. تبقى اختبارات TestClient القصيرة smoke فقط ولا تحمل اسم benchmark مؤسسي.

**الواجهة:** npm run test:load -- --profile tests/load/profile.json --output docs/verification/remediation/load-run. runner يرسل HTTP إلى base_url فعلي من env، ويتحقق أن DB PostgreSQL وهوية institutional والعامل heartbeat موجودة. profile يحتوي vus=100، warmup_seconds=300، duration_seconds=1800، seed_transactions=100000، tenants=2 على الأقل.

مزيج الحمل لكل مستخدم: 60% list/detail، و20% transitions بقضايا مستقلة، و15% upload 1MiB، و5% verify snapshot/export download. tokens لمستخدمين فعليين من issuer الاختباري، مع refresh طبيعي؛ لا dependency override. لا يحتسب زمن الإرسال إلى السلسلة ضمن قبول upload، ويقاس anchor/indexer lag منفصلاً.

- [ ] اكتب profile_rejects_short_duration_and_sqlite وasserts_100_concurrent_users وlatency_failure_changes_exit_code وcross_tenant_payload_is_never_returned. تلخص نتائج كل فئة منفصلة عن المتوسط العام.
- [ ] شغل node scripts/run-python.js -m pytest -q tests/load/test_profile.py؛ تثبت الاختبارات أن fixture الحالية لا تحقق شكل الاختبار المطلوب.
- [ ] نفذ اتصالاً خارجياً بالـASGI الفعلي، وإحصاء المستخدمين النشطين، وp50/p95/p99 وthroughput و5xx وconflicts المتوقعة/غير المتوقعة وoutbox age وRPC errors وCPU/RAM/I/O.
- [ ] جهز 100,000 معاملة من seed مسجل، وقضايا تكفي للمستخدمين دون تنافس اصطناعي شامل. احفظ مواصفات الجهاز وعدد العمليات والاتصالات ونسخ الصور وإعداد mining/finality؛ لا تستنتج TPS إنتاجياً من Hardhat محلي.
- [ ] شغل ملف الحمل الكامل 5+30 دقيقة، واختبر قصيراً مستقلاً قطع RPC/عامل ثم عودته؛ بعد الاستقرار قارن DB evidence/outbox/on-chain/request IDs. لا duplicate entries أو فقد ملفات أو عبور مؤسسة.
- [ ] اقبل فقط p95 read<=500ms وtransition<=1s وupload acceptance<=2s و5xx<1% وصفر خرق سلامة/عزل. تجاوز الحد يفشل المهمة مع أسباب ومقاييس، ولا يغير profile تلقائياً.
- [ ] سجل raw sanitized results وR19.md؛ حدّث performance.md بحدود البيئة، وراجع الفرق وcommit محصوراً. أعِد الحمل الكامل فقط بعد تعديل يمس السلوك المقاس أو إذا كانت الجولة غير صالحة.

## R20 — قبول نهائي من build نظيف وCI

**الاعتماد:** R01–R19. **المالك:** قائد التكامل + QA.

**الملفات:** تعديل .github/workflows/verify.yml وpackage.json وscripts/run-integration.js وrun-integration.ps1 وscripts/export-openapi.py وcheck-openapi.py وtests/e2e/trust-flow.spec.js. إنشاء scripts/check-remediation-evidence.py وtests/e2e/institutional-flow.spec.js وtests/e2e/failure-recovery.spec.js وshared/openapi-v3.json؛ ملفات التوليد تحفظ V2 وتضيف V3 ولا تستبدل أحدهما بالآخر.

**الواجهات:** أضف scripts root: contracts:size=node scripts/check-contract-size.js؛ verify:institutional=node scripts/run-integration.js --mode institutional؛ research:check=node scripts/run-python.js research/run_experiments.py --config research/protocol.json --check-gate؛ remediation:check=node scripts/run-python.js scripts/check-remediation-evidence.py.

research:check الفاشل يمنع RG-A وتفعيل ML؛ لا يمنع إصداراً rule_based إذا نجح باقي القبول وأظهرت وثيقته نتيجة البحث السلبية بوضوح. CI يميز activation gate عن baseline rules release؛ لا يغير exit code البحث إلى نجاح لإبقاء build أخضر.

- [ ] اكتب رحلة مستقلة: OIDC login→wallet challenge→case create→upload→outbox pending→معاملة فعلية→تأكيد→verify V3→report→ZIP→CLI مستقل. assertions تربط نفس institution/case/evidence/request/manifestDigest/blockHash عبر كل الحدود.
- [ ] أضف negative journey: مجهول401، دور غير مخول403، مؤسسة ثانية404، chain mismatch يمنع submit، توقيع مزور invalid، RPC outage unavailable، kill/restart worker لا يكرر evidence، حساب يتغير أثناء التوقيع لا يكمل بهوية سابقة.
- [ ] أضف fresh_build_no_stale_artifacts: compile من clean directory مع نسخ تعديلات المستخدم المقصودة وبصمتها، دون reset أو clean لمجلد المستخدم. لو استخدمت worktree فهو لا يحتوي uncommitted تلقائياً؛ انقل patch/الملفات المطلوبة صراحة إلى نسخة التحقق وسجلها.
- [ ] نفذ npm ci وnpm --prefix frontend ci وبيئة Python من lockfiles، ثم npm run compile وnpm run contracts:size وnpm run contracts:check وnpm run api:check وnpm run verify:contracts وnpm run verify:api وnpm run verify:frontend وnpm run verify:institutional. سجل command/cwd/exit لكل خطوة؛ الفشل يمنع بوابته.
- [ ] CI يستخدم خدمة PostgreSQL16 ودور محدود وOIDC fixture وعقدة EVM بقيودها القياسية وworkers فعليين، وينفذ migration وdeploy/verify قبل E2E؛ mocks تبقى في unit jobs فقط.
- [ ] check-remediation-evidence يفحص F01–F14→R00–R21، ووجود artifacts ونتائج البناء؛ يرفض CLOSED بلا proof أو proof من build مختلف. لا يتحقق من النجاح بالبحث عن كلمة PASS داخل README وحدها.
- [ ] نفذ npm run remediation:check؛ ثم اطلب مرور مراجعة مستقلة على الفرق النهائي الحساس والأدلة، مع إعادة اختبارات محددة إذا اكتشفت المراجعة تعديلاً لازماً. سجل R20.md وcommit محصوراً.

## R21 — إغلاق المخاطر والتسليم والترحيل

**الاعتماد:** R20. **المالك:** قائد التنفيذ/التشغيل؛ الإذن هنا إعداد التسليم المحلي، وليس تنفيذ cutover خارجي.

**الملفات:** تحديث docs/security/risk-register.md وdocs/verification/quality-gates.md وg1-trust.md وg2-institutional.md وg3-empirical.md وREADME.md. إنشاء docs/verification/remediation/release-acceptance.md وdocs/runbooks/remediation-cutover.md وdocs/verification/pilot-readiness.md وpilot-exit-criteria.md.

**حزمة التسليم:** build_id، source/lockfile hashes، deployed code sizes، ABI/OpenAPI hashes، manifest deployment_id، schema revision، data migration inventory، نتائج R01–R20، مفاتيح بأسمائها فقط، مخاطر متبقية، وخطة rollback. accepted_by وpilot_owner يتركان unsigned حتى توقيع الشخص الحقيقي؛ لا اختلاق اعتماد.

- [ ] افحص findings.csv: كل VERIFIED_FIXED له regression أخضر ودليل تكامل عند الحاجة؛ كل OPEN له أثر ومالك وموعد. لا تُغلق مشكلة لأن ملف خدمة أضيف أو اختبار قديم نجح.
- [ ] صحح أوصاف «100%/certified/تجربة كاملة» إلى نتائج محددة ومؤرخة؛ احفظ السجل التاريخي. RG-A الفاشل يظهر FAILED، وML=rule_based، دون منع نشر نتيجة أكاديمية سلبية صادقة.
- [ ] جهز ترحيلاً تجريبياً على نسخ اصطناعية: وقف writes، صالِح outbox، خذ backup، انشر2.1، ثبت manifest/cutover block، اختبر identities/files/snapshots، ثم استأنف. legacy contracts تبقى read-only؛ لا backfill attestation أو تغيير hashes قديمة.
- [ ] اختبر rollback rehearsal: يعطل الكتابة الجديدة ويعيد الخدمة للعرض فقط؛ يصالح المعاملات المبثوثة التي قد تتأكد لاحقاً. لا ينشر العقد غير الآمن ثانية أو يمكّن override منفرداً.
- [ ] جهز شروط تجربة30 يوماً: لا عبور مؤسسات/فقد دليل/توقيع مزور مقبول؛ مراجعة أسبوعية لتراكم outbox ورفع الأعطال؛ drill استعادة واحد؛ سجل حوادث؛ اعتماد بشري حقيقي عند النهاية. غياب جهة/بيانات/هوية حقيقية يبقي PILOT_NOT_STARTED.
- [ ] شغل npm run remediation:check وأرفق تقرير المراجعة النهائية، ثم سجل release-acceptance كـREADY_FOR_PILOT فقط بعد RG1–RG3، مع RG-A منفصلاً. الجاهزية التجارية تبقى مرحلة لاحقة في خطة22 أكتوبر.
- [ ] سلّم الروابط والقيود والخطوة التالية بوضوح؛ راجع الفرق وcommit محصوراً. لا ترفع ملفات المؤسسة أو تنشر خارجياً ضمن هذه المهمة.
