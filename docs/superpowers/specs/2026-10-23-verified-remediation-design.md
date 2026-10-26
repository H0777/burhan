# تصميم الإصلاحات المبنية على المراجعة — 23 أكتوبر 2026

الحالة: تصميم للتنفيذ، وليس شهادة بأن الإصلاحات نُفذت.

## 1. النطاق والأساس

المطلوب إصلاح المشروع الحالي مع المحافظة على أهدافه الثلاثة: البحث الأكاديمي، التجربة المؤسسية، ثم المنتج التجاري. الأولوية الآن لصحة الصلاحيات والأدلة والتشغيل؛ تبقى وظائف الاشتراكات والحصص والفوترة ضمن خارطة 22 أكتوبر بعد إغلاق هذه العيوب.

الأساس هو مراجعة نسخة HEAD = 1b94c5a مع تعديلات المستخدم الموجودة بتاريخ 2026-10-23. لذلك فإن رقم commit وحده لا يصف النسخة المراجعة. يجب تسجيل بصمة الملفات والتعديلات في R00 قبل التنفيذ. الأرقام التالية نتائج المراجعة السابقة، ولم تُعَد اختبارات المنتج أثناء كتابة هذه الخطة.

المشروع Solidity 0.8.20 وHardhat 2، وخادم Python/FastAPI/SQLAlchemy، وواجهة React 18/Vite 5، وقاعدة PostgreSQL 16 في الحاويات. لا يوجد تطبيق Tauri يستدعي ترحيله. تُحفظ الإصدارات الحالية وسياسة تحسين Solidity الحالية optimizer runs=200، ولا تُستبدل الأطر أثناء الإصلاح.

## 2. سجل المشكلات والأدلة

| المعرف | الأولوية | الدليل السابق | النتيجة المطلوبة | المهام |
|---|---|---|---|---|
| F01 | P0 | RoleManager.sol:315 يسمح باستدعاء testSetGeneration دون صلاحية؛ تغير جيل مدقق من 1 إلى 999 | إزالة المدخل من العقد والـABI ونقل أي حاجة اختبارية إلى harness | R01 |
| F02 | P0 | AuditEngine:435/539/626/745؛ بعد bootstrap نجح تجاوز التحذير منفرداً وتغيير السياسة مباشرة، مع enforcement=false وdelay=0 | كل قرار حوكمة يمر عبر مقترح مربوط بالفعل والهدف والهوية والوقت | R02، R03 |
| F03 | P0 | MultiSigApproval:331/407؛ تنفيذ تغيير دور بعد نحو 3 ثوانٍ؛ notBefore يساوي وقت الإنشاء | تأخير 24 ساعة للسياسات والأدوار والإعدادات، وإعادة فحص المصوتين وقت التنفيذ | R02، R03 |
| F04 | P0 | evidence_verifier:95 يقارن عدد الإدخالات؛ EvmRpcClient يعيد object placeholders | تحقق من المحتوى والملفات والعقد المسجل عند لقطة سلسلة واحدة | R07 |
| F05 | P0 | أداة verify-evidence-export قبلت ZIP بتوقيع INVALID-NO-PRIVATE-KEY وalgorithm=none، مع سجل ثقة غير موجود | توقيع غير متماثل حقيقي وسجل ثقة خارجي وفهرس كامل للملفات | R05، R09 |
| F06 | P0 | worker ينتج hashes مصطنعة دون RPC، ويثبت ANCHORED؛ PROCESSING لا يُسترد بعد تعطل العامل | تثبيت حقيقي قابل للاستئناف، مع lease وتأكيدات وإزالة الفروع المصطنعة | R08 |
| F07 | P1 | cases.py:74/106/127/151 تمرر identity إلى tenant_transaction الذي يتطلب session,institution_id | المسارات الأربعة تعمل عبر HTTP ومعاملات صحيحة وتعارضات متزامنة مضبوطة | R11، R12 |
| F08 | P1 | AuditEngine deployed bytecode = 27,533 بايت؛ نشر قياسي رُفض؛ الحد 24,576 | بناء جديد ونشر قياسي تحت ميزانية 24,000 بايت | R03، R04 |
| F09 | P1 | runtime-config مؤسسي مع isInstitutionalMode=false؛ /api/api/v2؛ عميل ثابت على localhost | مصدر إعداد واحد، مصادقة صحيحة، ومسار API واحد | R13، R14 |
| F10 | P1 | التطبيق يستخدم دور قاعدة البيانات audit_admin؛ اختبارات RLS تعتمد SQLite؛ OIDC معطل افتراضياً | مصادقة مؤسسية ملزمة وعزل فعلي بدور PostgreSQL محدود | R10، R11 |
| F11 | P1 | /ready لا يثبت اتصال DB/المخزن/العامل أو تحميل النموذج؛ manifest وRPC غير متصلين في الحاويات | جاهزية تقيس التبعيات الفعلية وتشغيل نظيف قابل للإعادة | R14، R15 |
| F12 | P1 | تقرير integrity_status يعتمد ANCHORED؛ مخزن الأدلة نص صريح؛ backup hash ذاتي | إثبات تحقق حقيقي، تشفير مخزن، واستعادة PostgreSQL مختبرة | R06، R09، R16 |
| F13 | P1 | recall=77% مقابل هدف 85%، وFPR يرتفع من 0 إلى 1.57 لكل ألف (نحو0.157%) مع SUPPORTED؛ تداخل زمني مثبت | فصل زمني وقرار نجاح محسوب، وتعطيل تفعيل النموذج عند الفشل | R17، R18 |
| F14 | P1 | حمل TestClient/SQLite قصير لا يثبت 100 مستخدم و100 ألف سجل و30 دقيقة | حمل خارجي حقيقي وتوثيق صادق لبوابات القبول | R19، R20، R21 |

P0 تعني مانع استخدام مؤسسي موثوق، وP1 تعني مانع قبول المرحلة ذات الصلة. هذا ترتيب تنفيذ هندسي وليس تصنيف CVSS أو حكم امتثال قانوني. بعض تفاصيل F10–F12 تحتاج اختبارات تثبيت في مهامها؛ لا تُحوّل الملاحظة الساكنة إلى ادعاء استغلال مثبت.

## 3. ثوابت عامة لا يجوز تجاوزها

- لا تعديل لملفات المستخدم غير المتعلقة بالمهمة، ولا git add شامل، ولا حذف لبيانات أو نشر على شبكة خارجية أثناء التنفيذ المحلي.
- institutional لا يسمح بهوية تجريبية أو RPC بديل أو hashes مختلقة أو توقيع احتياطي. demo يتطلب اختياراً صريحاً ويعرض بيانات تجريبية بوضوح.
- APP_MODE له قيمتان demo وinstitutional؛ غيابه أو فساد إعداد التشغيل يمنع بدء الخدمة المؤسسية، وفشل إعداد الواجهة يمنع أزرار الكتابة.
- لا اعتماد على role أو institution_id أو participant_id يرسلها المتصفح. تُستمد من هوية موثقة وعضوية مخزنة وربط محفظة مصادق عليه.
- تبقى خوارزمية Evidence V2: keccak256(abi.encode(...)) ومجال CYBER_AUDIT_EVIDENCE_V2 كما هي. إصلاح التحقق لا يعيد كتابة الأدلة القديمة.
- تعطى الحالة verified فقط بعد تحقق مستقل من المصدر والمحتوى والملفات واللقطة. خطأ الاتصال ينتج unavailable، والتعارض المثبت ينتج invalid.
- جميع مهام الخلفية والقراءات والكتابات المؤسسية تستخدم tenant context؛ عامل الخدمة لا يعمل بمستخدم PostgreSQL ذي BYPASSRLS.
- لا يعتبر تقرير مهمة أو نجاح اختبار وهمي دليلاً على إغلاقها؛ يلزم دليل من النسخة النهائية ومعرّف البناء والبيئة.

## 4. العقود والحوكمة — قرارات تنفيذ مقترحة

هذه خيارات هندسية للخطة وليست قرارات عمل نسبناها للمستخدم.

1. إصدار عقود جديد contract_version=2.1.0 ونشر جديد؛ العقود القديمة غير قابلة للإصلاح داخل مكانها ما لم يثبت وجود آلية ترقية سليمة. لا نفترض وجود proxy. تُسجل العقود القديمة legacy_read_only وتبقى قابلة للتحقق التاريخي.
2. يوجد مصدر تنفيذ حوكمة واحد MultiSigApproval. يمنع استدعاء EOA للمعدلات الحساسة بعد bootstrap، وتُحذف واجهات overrideWarning القديمة وواجهات السياسات المؤجلة الموازية من الإصدار الجديد. تُستبدل بتوابع تنفيذ governance-only. لا يُترك مفتاح يعيد تعطيل enforcement.
3. requires approvals=2 من مشاركين مختلفين غير صاحب المقترح. bootstrap يتطلب 4 هويات تصويت فريدة على الأقل من SUPER_ADMIN/AUDITOR؛ OPERATOR/REGULATOR لا يُحتسبان في النصاب. هذا يتحمل غياب مصوت واحد للقرارات العادية، ولا يضمن توافر نصاب كل قضية عند استبعاد أطرافها.
4. participant_id قيمة bytes32 مؤسسية ثابتة لا تشتق من عنوان المحفظة. لا يسمح بأكثر من محفظة فعالة للمشارك داخل المؤسسة. تدوير المحفظة يلغي القديمة ويزيد generation. لا يستطيع الجيل الرجوع إلى قيمة سابقة.
5. POLICY_CHANGE وROLE_CHANGE وSYSTEM_CONFIG: notBefore=createdAt+86,400 ثانية، باستثناء إلغاء صلاحيات الخدمة المحدد في البند8. TTL=259,200 ثانية لجميع الأنواع. لا يمكن خفض التأخير أو النصاب بهذه النسخة. OVERRIDE_WARNING وEMERGENCY_UNPAUSE لهما تأخير صفر بعد النصاب؛ فك الإيقاف مربوط بـpauseEpoch الحالي.
6. actionHash يرتبط بـchainId وعنوان الحوكمة وproposalId وproposalType والهدف وkeccak256(data) وcreatedAt وnotBefore وexpiresAt. تحفظ هوية المقترح وجيله وهوية كل مصوت وجيله وقت التصويت؛ تغير جيل المقترح يلزم مقترحاً جديداً. تنفذ بايتات data المخزنة فقط، مرة واحدة، مع إعادة فحص الصلاحيات والأجيال والنصاب والانتهاء والـepoch.
7. تستخرج أطراف التحويل من AuditEngine، وليس من حقول يختارها مقدم المقترح. يمنع طرف التحويل وهوية المشارك المطابقة له من تقديم أو الموافقة على تجاوز تحذيره. التنفيذ permissionless بعد الشروط لأنه لا يصنع قراراً جديداً؛ المنفذ لا يضيف صوتاً.
8. لكل proposalType قائمة target+selector مغلقة: تجاوز/فك إيقاف/سياسة إلى AuditEngine، وأدوار وتدوير محفظة إلى RoleManager. SYSTEM_CONFIG يقبل فقط ForensicTrail.setEvidenceWriter(address,bool) وInsiderActivityLog.setRecorder(address,bool) وsetBusinessHours(uint8,uint8). المنح وتغيير ساعات العمل ينتظران 24 ساعة؛ الإلغاء authorized=false له تأخير صفر مع بقاء الموافقتين. لا يسمح بترحيل governance أو تبديل العقود عبر call عام.
9. ميزانية deployed runtime bytecode <=24,000 بايت، وحد الشبكة 24,576؛ allowUnlimitedContractSize=false في جميع شبكات التحقق. يحذف المنطق المتوازي أولاً؛ إذا بقي الحجم أعلى من الميزانية تستخرج الحسابات الخالصة فقط إلى مكتبة مرتبطة، دون proxy أو delegatecall إلى عنوان قابل للتبديل.

## 5. عقد الثقة واللقطة والتحقق

يمتد ChainRegistry الحالي ليحل resolve(institution_id: str, deployment_id: str | None) -> DeploymentBinding. يحتوي الربط: deployment_id، institution_id، chain_id، addresses، deployed_code_hashes، deployed_at_block، confirmation_depth، contract_version، status. مصدره سجل يديره المشغل خارج طلب المستخدم. غياب الربط أو code hash أو أداة القراءة ينتج unavailable ولا يعني الثقة التلقائية.

في السلسلة المحلية confirmation_depth=2، وفي الإعداد المؤسسي الافتراضي 12، وتُخزن القيمة صراحة في السجل. لا تُوصف هذه القيم بأنها ضمان نهائية لكل شبكة. يُقرأ block_number=latest-depth+1 ثم تُثبّت block_hash. تُنفذ جميع eth_call/get_code عند block_number نفسه ويُعاد فحص block_hash قبل النتيجة. إعادة التنظيم إلى hash آخر تجعل اللقطة unavailable: snapshot_reorged.

واجهة رسمية جديدة POST /api/v3/evidence/verify:

    VerifyEvidenceRequest(case_id: str, evidence_ids: list[str], snapshot_id: str | None)
    VerificationResult(status: Literal["verified","invalid","unavailable"],
                       reasons: list[str], snapshot_id: str | None,
                       checked_evidence_ids: list[str], deployment_id: str | None)

الحالة 401 بلا هوية، و404 للقضية/الدليل خارج المؤسسة، و422 لطلب مشوه/معرفات مكررة. بعد الإذن يعيد التحقق 200 مع status صريح؛ لا تخلط unavailable مع verified. identifiers النصية في API تشير إلى EvidenceObject؛ أرقام incident/evidence على السلسلة uint256 تُحل من قاعدة البيانات وتصدر إلى JSON كسلاسل عشرية لمنع فقدان دقة JavaScript. لا يقبل V3 entries أو chain_id أو contract_address من المتصفح.

في institutional تعيد واجهة V2 القديمة للتحقق 410 مع رابط V3؛ في demo يمكن إبقاء أداة حساب محلية لكن provenance_status=demo وغير قابلة للتصدير الرسمي. هذا كسر تعاقد مقصود ينعكس في OpenAPI والواجهة واختبارات الانتقال، ولا يغير hash schema V2.

يقرأ AnchorReader الإدخالات الحقيقية كاملة عند اللقطة، ويقارن genesis=bytes32(0)، وترتيب المعرفات، والروابط، وجميع حقول الهاش، والعدد والرأس. يتحقق من ترخيص الكاتب قبل حدث الإضافة بترتيب (blockNumber,transactionIndex,logIndex)، وليس حالة نهاية البلوك؛ يضمن ذلك صحة الإضافة ثم الإلغاء في البلوك نفسه. يتحقق أيضاً من سجل خدمة التثبيت الموقع، وهوية المؤسسة والقضية ونسخة الكائن وSHA-256 للبايتات الحقيقية. الكاتب الملغى لاحقاً لا يبطل دليلاً كان مصرحاً عند الإضافة. غياب تاريخ الترخيص اللازم ينتج unavailable.

تُحفظ VerificationSnapshot مع block hash وhead/count ونسخ الملفات ونتائج الفحوص. إضافة دليل لاحق لا تغير لقطة سابقة سليمة. الدليل القديم الذي يفتقد بيان مصدر موقع يخرج legacy_unattested؛ لا يُمنح تحقق رسمي كامل بإضافة توقيع بأثر رجعي.

## 6. التوقيع والمخزن والتصدير

يعتمد التوقيع Ed25519 بواسطة cryptography؛ لا توجد HMAC بمفتاح مشتق من institution_id. لا تدخل المفاتيح الخاصة Git أو ZIP أو سجلات التشغيل. لكل مؤسسة مفتاح مسمى key_id؛ verifier يحصل على سجل الثقة من مسار خارجي مطلوب، لا من مفتاح مرفق بالحزمة.

Canonical JSON للأجسام الموقعة: UTF-8، sort_keys=True، separators=(",",":")، ensure_ascii=False، allow_nan=False؛ يقتصر المخطط على strings/integers/booleans/lists/objects/null ولا يسمح floats أو duplicate JSON keys. يبقى المحتوى النصي كما هو دون Unicode normalization. signature = Ed25519(domain + NUL + canonical_bytes). المجالات مختلفة: AML_SERVICE_MANIFEST_V1 وAML_DOSSIER_V1 وAML_BACKUP_V1.

سجل الثقة: institution_id، key_id، public_key، valid_from، valid_until، status، revoked_at، invalid_from. status=compromised يبطل كل التواقيع بدءاً من invalid_from؛ إذا غاب وقت موثوق للاختراق تبطل جميع تواقيع المفتاح. التقاعد المعتاد retired يقبل البيان الذي يثبت أنه وُقع خلال الصلاحية وفق وقت التثبيت/الإصدار الموثوق؛ لا يُصدّق وقت يختاره ZIP وحده.

مخزن الأدلة يحتفظ بحد 25*1024*1024 بايت للملف، ونسخ append-only. AES-256-GCM بمفتاح بيانات عشوائي لكل كائن، ملفوف بمفتاح مؤسسة خارجي مع key_id. AAD يربط المؤسسة والدليل والنسخة. لا تُغير rotation الملفات القديمة؛ يُحتفظ بمراجع مفاتيحها لاستعادتها. الحماية من overwrite تعتمد نشر نسخة ذرية no-replace، ومسار داخل جذر المخزن، ومنع symlink traversal؛ وجود ملفات على القرص وحده ليس WORM قانونياً.

دليل الخدمة الموقّع يربط institution_id، case_id، evidence_id، object_version، file_sha256، size، anchor_request_id، participant_id، issued_at، key_id. يُحفظ قبل إنشاء حدث outbox ولا يعاد إنشاؤه من إدخال المتصفح.

في ForensicTrail 2.1 تضاف submitEvidenceAttested(...,bytes32 manifestDigest) مع خريطة requestId إلى manifestDigest وحدث EvidenceManifestAnchored. envelope={body,algorithm:"Ed25519",signature:<base64>}، وbody يتضمن key_id. digest=SHA-256(canonical signed envelope)، بما يشمل التوقيع نفسه؛ يحفظ في معاملة الإضافة نفسها ويشمل payloadHash الخاص بمنع التكرار. لا يضاف إلى Evidence V2 entry hash ولا يغيره. يقارن verifier البيان والتوقيع بالتزام السلسلة، ووقت بلوك الالتزام حد زمني موثوق لوجودهما معاً. لا توجد دالة لإلحاق هذا الالتزام بأدلة قديمة.

يبقى submitEvidence القديم لآثار الإنذار الآلية الحالية التي ينشئها AuditEngine، وتُصنف chain_generated_unattested؛ لا تتحول إلى إثبات ملف موقع أو تحقق منشأ كامل. المعاملة الآلية لا تنكسر بسبب عدم امتلاك العقد مفتاح توقيع خارج السلسلة. خدمة ملفات المؤسسة تستخدم attested حصراً. لقبول توقيع مفتاح retired في offline يلزم checkpoint موثوق خارج ZIP يربط digest بوقت/بلوك قبل انتهاء المفتاح؛ بدونه تكون النتيجة unavailable: historical_key_time_unproven. المفتاح active حالياً يمكن التحقق به دون ادعاء إثبات زمن توقيع تاريخي.

حزمة التصدير كاملة فقط: manifest.json وsignature.json وreport.md وملفات الأدلة وبيانات تحققها. manifest يتضمن كل المسارات والأحجام وSHA-256 بما فيها report.md، باستثناء manifest.json وsignature.json لتجنب الدوران. يحمي التوقيع manifest، وهو يحمي باقي الحزمة. checksums.sha256 اختياري للاستخدام اليدوي وغير مصدر ثقة. غياب ملف، أو EVIDENCE-STUB، أو عضو زائد، أو مسار مكرر/متجاوز، أو توقيع غير معروف يفشل.

حد حزمة V1: 200 ملف دليل، و512 MiB إجمالي بايتات غير مضغوطة، و1,000 عضو ZIP إجمالاً، ورفض symlinks والمسارات المطلقة و.. والمحارف الضابطة والتصادم بعد تطبيع / وحالة الأحرف. لا يُفك ZIP عشوائياً إلى القرص.

أداة التحقق المستقلة تخرج bundle_status=verified|invalid|unavailable وanchor_status=verified|invalid|unavailable|not_checked. بلا RPC يمكن إثبات bundle_status فقط؛ لا تطبع VERIFIED_ON_CHAIN. exit code: 0 لحزمة صحيحة في وضع offline؛ 1 للتلاعب؛ 2 لثقة/تبعية غير متاحة؛ ومع --online يلزم نجاح الحزمة والسلسلة لإرجاع 0. هذه الحدود تمنع إعادة تسمية سلامة ZIP كدليل على الحقيقة أو المقبولية القضائية.

## 7. العامل وصندوق الصادر

حالات outbox: PENDING، PROCESSING، SUBMITTED، COMPLETED، FAILED، DEAD. حالات المرساة: PENDING، SUBMITTED، ANCHORED، REORGED، FAILED. لا تعني SUBMITTED نهائية المعاملة.

claim_batch(session, institution_id, worker_id, now, limit=20) -> list[Outbox] يستخدم FOR UPDATE SKIP LOCKED، lease=60 ثانية، وتجديداً كل 20 ثانية مع owner token. استعادة lease منتهٍ لا تنتج إرسالاً جديداً قبل فحص request_id/tx_hash. retries بحد 5 وبفواصل 5،30،120،600،1800 ثانية؛ المحاولة الخامسة الفاشلة تضع DEAD مع سبب وإمكانية إعادة جدولة صريحة مسجلة.

قبل إرسال معاملة، يُحفظ signed raw transaction وtx_hash وnonce محميّة في DB؛ يعاد بث المعاملة نفسها بعد التعطل. العنوان حصري لخدمة التثبيت ولا يستخدمه مشغل أو برنامج آخر. nonce allocation متسلسل بقفل PostgreSQL لكل chain+signer عبر جميع العمال. لا يوجد استبدال تلقائي لمعاملة عالقة؛ بعد 300 ثانية يُرفع تنبيه وتوقف معاملات جديدة لهذا المرسل، وتستمر المصالحة دون إعلان فشل نهائي أو تغيير payload. استهلاك nonce بمعاملة مجهولة يوقف المرسل ويطلب إجراء تشغيل موثق. لا يمنح ذلك المعاملة اللاحقة نجاحاً وهمياً.

getEvidenceByRequestId هو مرجع منع التكرار. لإنشاء incident تُضاف createIncidentForCase(bytes32 caseReferenceHash,bytes32 titleHash,bytes32 severityHash) وخريطة lookup ثابتة؛ إعادة نفس المرجع ونفس metadata تعيد نفس incident، والاختلاف يفشل. caseReferenceHash=keccak256(abi.encode(chainId,ForensicTrail,institutionRefHash,caseIdHash))، بلا أسماء أو بيانات حساسة علنية. التثبيت مربوط بـcase_incident_mapping الحقيقي لا incident_id=1. لا تتحول المرساة إلى ANCHORED إلا بعد receipt ناجح وعدد التأكيدات والتحقق من البلوك ومطابقة entryHash مع الملف والبيان.

توجد عمليتا تشغيل مستقلتان anchor وindexer؛ لا تعتمد أي منهما على وصول طلب HTTP. يعالج indexer reorg بإرجاع checkpoint آخر صحيح وإبطال الإسقاطات/اللقطات المتأثرة دون حذف الملفات الأصلية. قيود unique تمنع تكرار الطلب والحدث عبر إعادة المحاولة.

## 8. الهوية والبيانات والتكامل

OIDC مطلوب في institutional: issuer وaudience وalgorithms allowlist وexp/iat/nbf/sub إلزامية، clock skew=60 ثانية. membership النشطة هي مصدر الدور؛ لا تُنشأ عضوية من JWT role claim. challenge المحفظة صالح 300 ثانية، أحادي الاستخدام، مربوط بالمستخدم والمؤسسة وchain/domain، ويحفظ في DB. تتطابق هوية participant مع RoleManager، وتُرفض generation ملغاة.

يكون PostgreSQL app role غير مالك، NOSUPERUSER NOBYPASSRLS، ولا يملك DDL. migration role منفصل. tenant_transaction يستخدم SELECT set_config('app.current_institution_id', :id, true) ضمن معاملة واحدة؛ السياق لا يتسرب إلى اتصال يعاد استخدامه. يعتمد بدء الإنتاج على migrations؛ create_all وseed institution محصوران بالاختبار/demo.

تحديث حالة القضية يستخدم SQL compare-and-swap على institution_id+case_id+version، ويكتب الحالة والحدث ونتيجة idempotency في المعاملة نفسها. winner واحد و409 للطلب المنافس. idempotency مربوط بالمؤسسة والمستخدم والطريقة والمسار وبصمة كل الحقول الدلالية؛ تغير description/severity/new_assignee_sub لا يعاد كنجاح قديم.

RuntimeConfig مصدر الواجهة الوحيد بعد التحميل: app_mode، api_origin، chain_id، rpc_url، deployment_id، contracts، وoidc={authority,client_id,redirect_uri,scope} المطلوبة في institutional. تسجيل دخول الواجهة Authorization Code مع PKCE عبر oidc-client-ts، دون client_secret أو لصق token يدوياً؛ callback=/auth/callback على origin الواجهة، مع state/nonce والتحقق من العودة. api_origin="" للـsame-origin أو origin مطلق بلا /api؛ client يضيف /api/v2 أو /api/v3 مرة واحدة. chainId يجب أن يطابق تماماً حتى محلياً. تغير الحساب/الشبكة يلغي الهوية والتوقيع الجاري ويوقف الكتابة حتى إعادة الربط.

Docker development يظل demo صريحاً ومنافذ localhost فقط. اختبار institutional يعمل بعقدة محلية دون ادعاء صلاحية نشر عام، وOIDC اختباري حقيقي، ودور PostgreSQL محدود. عامل النشر ينتج manifest في volume مخصص، تقرؤه API والعمال والواجهة read-only بعد نجاح نشر وتحقق code hashes. لا تحفظ signer secrets في runtime-config.

## 9. الجاهزية والاستعادة والبحث

/live يفحص بقاء العملية فقط. /ready يعيد 503 إذا فشلت DB migrations/RLS role، أو هوية institutional، أو سجل النشر/code hashes، أو RPC، أو قراءة/كتابة canary للمخزن، أو مفتاح التوقيع/التشفير، أو heartbeat العمال >120 ثانية، أو عمر أقدم outbox جاهز >300 ثانية. عند تفعيل ML يلزم تحميل النموذج المسجل والتحقق من hash وتشغيل استدلال واحد؛ ML المعطل صراحة لا يفشل الجاهزية.

النسخ المؤسسي يستخدم pg_dump بصيغة custom وsnapshot متسق، وفهرس أدلة من لقطة DB نفسها وملفات append-only المشار إليها. تستخدم عملية الصيانة وحدها audit_backup بحساب NOSUPERUSER BYPASSRLS وSELECT فقط لجميع بيانات النسخ؛ هذا استثناء مقصود لقراءة نسخة كاملة، ولا تصل بيانات اعتماده إلى API أو العمال أو المتصفح. الاستعادة بحساب منفصل إلى DB/مسار جديدين فقط، ولا تكتب فوق النظام القائم. الحزمة الداخلية المشفرة تضم dump وفهرس الملفات؛ manifest خارجي موقع يحمي SHA-256 للـciphertext وwrapped key وnonce/tag وبصمة الفهرس الداخلي. تتحقق الثقة الخارجية أولاً ثم يفك GCM ثم يفحص الفهرس الداخلي. تحفظ مراجع المفاتيح دون مفاتيحها. الهدف المقترح RPO<=15 دقيقة وRTO<=120 دقيقة، ويُقاس ويُحجب قبول التشغيل إذا لم يثبت؛ ليس وعداً محققاً.

البحث يستخدم train/validation/test مفصولة زمنياً وبحسب هوية المشارك: اختيار cutoffs زمنية أولاً؛ train يحتفظ بما قبل cutoff الأول، وvalidation بمشاركين أول ظهورهم بعده وآخر ظهورهم قبل cutoff الثاني، وtest بمن أول ظهورهم بعد cutoff الثاني. تستبعد من التقييم السجلات المستقبلية لمشاركي train وكل مشارك يعبر validation/test مع تسجيل السبب؛ لا نقل لسجل مستقبلي إلى التدريب لتعويض الحجم. يرفض التشغيل مجموعة فارغة أو أقل من 100 عينة أو غياب إحدى الفئتين في أي split. تُسجل كل المعرفات والبصمات والإصدارات الفعلية. لا يُدرّب scaler أو feature history على test، ولا يُعدل threshold بعد الاطلاع على test.

بوابة البحث تحافظ على research/protocol.json: recall_test>=0.85 وFPR<=50 لكل ألف وPR-AUC>=0.80 وscoring p95<=25ms. وحدة FPR الداخلية نسبة0..1، وعرض per_1000 يضربها في1000؛ 1.57 لكل ألف تساوي0.00157 لا0.0157. بوابة تفعيل ML الإضافية: recall لا يقل عن baseline وFPR لا يزيد عنه مع تحسن صارم في أحدهما؛ baseline FPR=0 لا يسمح بقول «خفض الإيجابيات الكاذبة» مع FPR أعلى. النتائج الحالية المذكورة في §2 تعني FAILED وفق هذه القاعدة؛ يبقى التشغيل rule_based. هذه سياسة قبول هندسية مقترحة ولا تدعي معياراً تنظيمياً.

اختبار الحمل: HTTP خارجي إلى عمليات فعلية مع PostgreSQL و100,000 معاملة و100 مستخدم متزامن مدة 30 دقيقة بعد warm-up خمس دقائق. الحدود المقترحة: p95 لقراءة القضايا<=500ms، وتعديل القضايا<=1s، وقبول upload<=2s لملف 1MiB دون انتظار التثبيت، ومعدل5xx<1%، وصفر عبور مؤسسات/فقد أدلة/تكرار انتقال. زمن تأكيد السلسلة يقاس منفصلاً. تُسجل CPU/RAM/قرص والشبكة والبيئة قبل مقارنة النتائج.

## 10. البوابات والمخرجات

- RG0: نسخة أساس محفوظة، كل F مربوط باختبار، ومنع ادعاءات تحقق غير مدعومة أثناء الانتقال.
- RG1: R01–R04؛ حوكمة بلا bypass ونشر قياسي وABI مطابق.
- RG2: R05–R13؛ هوية وعزل وأدلة موقعة ومثبتة فعلياً ومسارات وواجهة صحيحة.
- RG3: R14–R16 وR19–R20؛ تشغيل نظيف وحمل واستعادة ومراجعة مستقلة للفرق النهائي.
- RG-A: R17–R18؛ بحث قابل للإعادة؛ يسمح بنشر نتائج سلبية صادقة، ولا يسمح بتفعيل ML الفاشل.
- RG4: R21؛ سجل مخاطر صادق، حزمة تسليم، ثم تجربة مؤسسية 30 يوماً. لا يساوي اجتياز الإصلاحات نجاح التجربة الفعلية أو الجاهزية التجارية.

تفاصيل التنفيذ والتسلسل في [خارطة الإصلاح](../plans/2026-10-23-remediation-roadmap.md). تعود المهام التجارية المستقبلية إلى [خطة المرحلة التجارية الأصلية](../plans/2026-10-22-phase-4-commercial-readiness.md) بعد RG4.
