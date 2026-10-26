# Trust and Integration Implementation Plan — الحزمة الأولى

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** إغلاق الثغرات المثبتة وإنتاج تدفق حقيقي قابل للاختبار بين الواجهة وPython والعقود المحلية.

**Architecture:** عقود V2 جديدة، مخطط أدلة مشترك، API V2 صارم، وعميل مولد؛ demo معزول. Bootstrap مرحلي لإغلاق دورة مراجع العقود الخمسة.

**Tech Stack:** Solidity 0.8.20/Hardhat 2، React 18/Vite 5، FastAPI/Python 3.11، Vitest/Testing Library وPlaywright عند إضافة الاختبارات.

**Spec:** [التصميم §3–8 والمتطلبات R01–R07,R10,R15,R18](../specs/2026-10-22-three-track-development-design.md).

## Global Constraints

- الحفاظ على React 18 وVite 5 وFastAPI وSolidity 0.8.20/Hardhat 2 في مرحلة التثبيت؛ الترقيات الكبيرة لها مهمة مستقلة لاحقاً.
- بيانات المال strings للوحدة الصغرى؛ ETH scale=18؛ لا تغيير ضمني لقيمة سياسة العقد 10,000 ETH.
- no replay، no silent fallback، ولا امتياز دائم للناشر بعد bootstrap.
- هذه مهام مستقبلية. المسارات الموسومة Create غير موجودة بعد؛ أوامر الاختبار لها Working directory واضح.

## Review Focus

1. حساب غير مخول يزوّر نشاطاً أو يضيف دليلاً: T02.
2. اقتراح قديم/منتهي/مصوت مسحوب الدور أو رفع إيقاف قديم: T03.
3. دليل أول/أخير/مقتطع/من عقد آخر/نص Unicode معدّل: T04/T05.
4. شبكة بchainId صحيح لكن عقد خاطئ، أو رفض محفظة المستخدم: T08/T10.
5. فشل خدمة أثناء اعتماد الواجهة أو التقرير لا يظهر نجاحاً: T08/T09/T12.

## خريطة الملفات والملكية

| الوحدة | الملفات | المالك |
|---|---|---|
| خط الأساس | docs/verification/baseline-2026-10-22.md | QA/قائد |
| كتابة وحوكمة | contracts/access/*، contracts/forensics/*، contracts/AuditEngine.sol، interfaces، test/* | Web3 |
| ترميز الأدلة | contracts/libraries/EvidenceHashing.sol، shared/fixtures/evidence-v2.json، ai-engine/app/services/evidence_verifier.py | Web3 ثم Backend بعد تجميد fixture |
| API والسياسات | ai-engine/app/schemas/*، routes/v2/*، services/policy_service.py | Backend |
| عميل وربط واجهة | frontend/src/api/*، contracts/generated/*، hooks، components | Frontend |
| توليد وتشغيل | scripts/export-contracts.js، export-openapi.py، deployment manifests، Compose، CI | DevOps مع مالك واحد لملفات التكامل |

لا تعديل الملفات المشتركة بالتوازي. أسماء الاختبارات الآتية عقود قبول؛ يمكن تجميع الحالات باستخدام parameterization مع الحفاظ على المعنى.

## T01 — حفظ خط الأساس وتجارب إعادة المشاكل (1–2 يوم عمل)

**المالك:** QA/القائد. **الاعتماديات:** لا شيء. **المتطلبات:** R16,R18.

**Files:** Create `docs/verification/baseline-2026-10-22.md`; Create `test/security/ObservedRegressions.test.js`; Create `ai-engine/tests/test_observed_regressions.py`.

**Interfaces:** تنتج مصفوفة findings -> test_name -> expected behavior، وجرد الملفات المعدلة/غير المتتبعة بلا نسخ أسرار إلى التقرير.

- [x] سجّل إصدارات الأدوات وحالة Git ونتائج `npm run test:contracts` من الجذر، و`npm --prefix frontend run build` و`npm --prefix frontend run lint`؛ Python من ai-engine: `python -m pytest -q tests` مع PYTHONPATH=مجلد ai-engine.
- [x] أضف اختبارات إعادة الحالة: outsider_logs_for_other_operator، outsider_changes_business_hours، approved_proposal_reused، altered_content_claimed_verified، frontend_payload_mismatch؛ assertions تتوقع الرفض/invalid.
- [x] شغّل `npx hardhat test test/security/ObservedRegressions.test.js` و`python -m pytest -q tests/test_observed_regressions.py`؛ سجّل الفشل الفعلي قبل أي إصلاح. لا يترك الاختبار failing في بوابة الإصدار النهائية.
- [x] اربط كل اختبار بمالك T02/T03/T05/T07؛ احتفظ بنتائج baseline دون إضافة badges تغطية جديدة.
- [x] راجع ثم احفظ ملفات المهمة فقط في commit محلي عند بدء التنفيذ؛ لا `git add .` مع حالة العمل الحالية.

**القبول:** يمكن لمهندس آخر إعادة كل مشكلة وفهم أصلها؛ لا تعديلات في كود المنتج في T01.

## T02 — تقييد التسجيل والكتابة وbootstrap (2–4 أيام)

**المالك:** Web3. **الاعتماديات:** T01. **المتطلبات:** R01,R03,R18.

**Files:** Modify `contracts/access/MultiSigApproval.sol` لمنطق bootstrap فقط، `contracts/forensics/InsiderActivityLog.sol`, `contracts/forensics/ForensicTrail.sol`, `contracts/access/RoleManager.sol`, `contracts/AuditEngine.sol`, `contracts/interfaces/IRoleManager.sol`, `contracts/interfaces/IForensicTrail.sol`; Create `test/security/WriteAuthorization.test.js`; تحديث fixtures الاختبارات الحالية المتأثرة. منطق التصويت والتنفيذ النهائي في MultiSig يتبع T03 بعد دمج T02، دون مالكين متزامنين.

**Interfaces:** `MultiSigApproval(address bootstrapAuthority)` ينشر أولاً؛ `RoleManager(address initialGovernance)` وبقية العقود تنشر بعدها بسلطته؛ `setRecorder(address,bool)` و`setEvidenceWriter(address,bool)` للحوكمة؛ `configureContracts(...)` و`bootstrapParticipants(...)` مرة للسلطة المؤقتة؛ `finalizeBootstrap()` يفحص المراجع و4مشاركين ويزيل bootstrapAuthority. كل التنفيذ العادي معطل قبله. `logActivity` يحتفظ بمعاملاته ويُتاح للrecorder فقط. الأدوار خارج bootstrap لا تتغير إلا عبر multiSig.

- [x] اكتب اختبارات: outsider والAUDITOR لا يسجلان باسم آخر؛ تغيير الساعات من غير الحوكمة يرفض؛ عقد مرخص يسجل operator الحقيقي من سياق التنفيذ؛ writer غير مسجل يرفض؛ bootstrap لا يقبل EOA كعقد أو ربطاً ثانياً أو إقفالاً ناقصاً.
- [x] شغّل `npx hardhat test test/security/WriteAuthorization.test.js`؛ أثبت فشل الضوابط الناقصة.
- [x] نفذ allowlists وربطاً أحادي الاستخدام وأحداث تغيّر إعدادات؛ ارفض صفر العنوان؛ اجعل config بعد الإقفال عبر الحوكمة فقط. أضف إدارة ساعات العمل مع حفظ السياق UTC وعدم الادعاء أنها تقويم بغداد.
- [x] شغّل اختبار المهمة ثم `npm run test:contracts`؛ أصلح fixtures لتنشئ النظام الجديد صراحة. لا تحفظ legacy unsafe deployments في مسار institutional.
- [x] راجع كل external/public mutator وحدثه، ثم commit انتقائي.

**القبول:** استدعاء غير مخول لا يغير العداد أو الأدلة أو الإعدادات؛ لا مسار bootstrap مفتوح بعد finalize.

## T03 — حوكمة ذرية وموافقات محددة الفعل (4–7 أيام)

**المالك:** Web3. **الاعتماديات:** T02. **المتطلبات:** R02,R03.

**Files:** Modify `contracts/access/MultiSigApproval.sol`, `contracts/access/RoleManager.sol`, `contracts/AuditEngine.sol`; Create `test/security/GovernanceExecution.test.js`; Modify `test/MultiSigApproval.test.js`, `test/EnterpriseFeatures.test.js`.

**Interfaces:** `createProposal(ProposalType,address,bytes,bytes32) returns(uint256)`؛ `approveProposal(uint256)`؛ `executeProposal(uint256)`؛ `getProposal(uint256)` و`getApprovers(uint256)`. `Proposal` يضم actionHash/target/callData/notBefore/expiresAt/status. `RoleManager.getParticipant(address)` يرجع participant_id/authorization_generation/role، وenroll/rotate عبر حوكمة؛ صوت يخزن participant_id/generation. `AuditEngine.pauseEpoch()`؛ وظائف التنفيذ الحساس `onlyGovernance`؛ واجهة الاستخدام تتجه إلى executeProposal بدلاً من reuse proposalId في دوال مستقلة.

- [x] اكتب assertions: التنفيذ الأول يغير الحالة مرة، الثاني يرفض؛ تغيير target/calldata/type يرفض؛ proposer وطرفا المعاملة لا يصوتون؛ محفظتان لparticipant نفسه لا تمنحان صوتين؛ سحب الدور ثم إعادته لا يحيي generation قديمة؛ expiresAt يطبق بعد APPROVED؛ pauseEpoch قديم لا يرفع إيقافاً جديداً. اختبر4مشاركين وغياب1 مع بقاء تدوير المفتاح ممكناً بالموافقات العادية.
- [x] أضف اختبار atomicity: هدف يرجع revert يترك الاقتراح APPROVED والحالة كما كانت؛ approval لا يصدر ProposalExecuted؛ نشر/تدوير governance لا يمنح الناشر استثناء.
- [x] شغّل `npx hardhat test test/security/GovernanceExecution.test.js` قبل الإصلاح ثم نفذ hash/typed allowlist/status machine في التصميم §5؛ لا delegatecall؛ caller العقد الهدف هو multiSig؛ هوية طالب التنفيذ تسجل عبر حدث/معامل موثق.
- [x] شغّل مجموعة الحوكمة وجميع العقود؛ اختبر تغيير timelock إلى صفر مرفوضاً، ورفع الإيقاف بنوع مستقل، وسياسة جديدة تستلزم اقتراحاً جديداً مطابقاً.
- [x] راجع diff مستقلاً واحفظ commit للمهمة؛ حدّث بيان عدم التوافق V2 وتوجيهات نشر المؤسسة.

**القبول:** لا طريق مباشر من admin/ناشر إلى تجاوز التحذير أو تغيير دور/سياسة/مُسجّل خارج الحوكمة. تظل emergencyPause متاحة فوراً للدور المخول، ورفعها محكوم.

## T04 — مخطط أدلة V2 وfixtures مشتركة (2–3 أيام)

**المالك:** Web3 مع Backend/Frontend كمستهلكين. **الاعتماديات:** T02؛ مراجعة T03 قبل دمج عقد ForensicTrail. **المتطلبات:** R04,R06,R18.

**Files:** Create `contracts/libraries/EvidenceHashing.sol`, `shared/fixtures/evidence-v2.json`, `test/forensics/EvidenceHashing.test.js`, `ai-engine/app/schemas/evidence.py`, `ai-engine/tests/test_evidence_hashing.py`, `frontend/src/utils/evidenceHash.js`, `shared/tests/evidence-hash.test.mjs`; Modify `contracts/forensics/ForensicTrail.sol`, interfaces.

**Interfaces:** `EvidenceHashing.hashEntry(EvidenceV2) returns(bytes32)`؛ Python `hash_entry(entry: EvidenceV2) -> str`؛ JS `hashEvidence(entry) -> string`. الحقول والترتيب والأنواع حرفياً في التصميم §6. CREATE incident يستقبل titleHash/severityHash؛ `submitEvidence(incidentId,anchorRequestId,typeHash,descriptionHash,fileSha256)` و`getEvidenceByRequestId(bytes32)` يتبعان dedup contract في §5؛ submittedBy هو الكاتب الفعلي. تعدل نداءات AuditEngine الآلية لتنشئ requestId ثابتاً لكل فعل؛ راجع caller/ABI والاختبارات ذات الصلة ضمن نفس المهمة.

- [x] أضف fixtures لبداية بسابق صفري، ودليل ثانٍ، وUnicode، وuint256 كبير، وتغيير كل حقل؛ القيم المتوقعة تصدر وتراجع من ترميز EVM مستقل قبل تثبيتها. اختبر requestId مكرراً بنفس payload يعيد evidenceId نفسه بلا زيادة عداد، ونفس requestId بمحتوى أو كاتب آخر يرفض.
- [x] شغّل الاختبارات الثلاثة قبل إنشاء الدوال؛ لا تستخدم verifier نفسه لتوليد expected values.
- [x] نفذ abi.encode V2 وفصل hash الملف SHA-256 عن hash السجل keccak256؛ legacy_v1 قارئ منفصل، بلا تغيير محتوى السلسلة القديمة.
- [x] شغّل من الجذر `npx hardhat test test/forensics/EvidenceHashing.test.js` و`node --test shared/tests/evidence-hash.test.mjs`، ومن ai-engine `python -m pytest -q tests/test_evidence_hashing.py`؛ Node builtin runner يستورد evidenceHash.js مباشرة ولا ينتظر إعداد Vitest في T08؛ مخرجات اللغات الثلاث يجب أن تطابق fixture نفسها.
- [x] وثّق schema_version ومفاتيح registry ثم commit بعد مراجعة الترميز.

**القبول:** أي تغيير محتوى/قضية/عقد/شبكة يغير البصمة؛ لا حقول حساسة خام في معاملات V2.

## T05 — تحقق مستقل بثلاث حالات (2–3 أيام)

**المالك:** Backend. **الاعتماديات:** T04. **المتطلبات:** R04,R05,R15.

**Files:** Create `ai-engine/app/services/evidence_verifier.py`, `ai-engine/app/routes/v2/evidence.py`, `ai-engine/tests/test_evidence_verifier.py`; Modify `ai-engine/app/schemas/evidence.py`, `ai-engine/app/routes/forensic_report.py`, `ai-engine/app/services/gemini_service.py` لمنع إعلان تحقق ثابت حتى في v1.

**Interfaces:** `verify_evidence_chain(entries, file_reader, anchor_reader, snapshot) -> VerificationResult`؛ `AnchorReader.get_anchor(institution_id,incident_id,snapshot?) -> {chain_id,contract_address,count,head,block_number,block_hash}`؛ `EvidenceRepository.resolve(identity,case_id,evidence_ids)` يجلب ملفات/manifest/entries المصرح بها. POST `/api/v2/evidence/verify` يستهلك مراجع فقط حسب §7. في G1 registry ثابت وFixtureEvidenceRepository في test harness فقط؛ لا يفعّل institutional verifier قبل ربط التخزين T14. legacy result يفصل integrity عن provenance المحدودة.

- [x] اكتب اختبارات تغيير محتوى مع ثبات entryHash، تغيير الرابط الأخير، حذف البداية/النهاية، قائمة فارغة، عنصر {}، مصدر عقد من خارج registry، وتعطل RPC؛ النتائج invalid/422/unavailable حسب التصميم.
- [x] شغّل من ai-engine `python -m pytest -q tests/test_evidence_verifier.py` وتحقق من فشل الحالات الحالية.
- [x] طبق إعادة حساب كل بصمة، وفحص ترتيب الحادثة/الهويات/الأنواع، ثم مطابقة anchor/count؛ أخطاء المورد unavailable مع reason؛ لا True ثابت في التقرير أو health.
- [x] أضف fixtures V1 معلومة من نواتج العقد القديم، واختبر canonical block/hash وsnapshot سابقة بقيت صحيحة بعد إضافة دليل؛ integrity القديمة لا تصنف provenance موثوقة. شغّل RPC محلياً حقيقياً لحالة واحدة على الأقل؛ الملفات/human identities في G1 fixtures معلنة، لا تدّعي أن الاختبار أثبت تخزيناً أو enrollment حقيقيين.
- [x] راجع التضليل المحتمل في labels والحقول ثم commit.

**القبول:** سلسلة ذاتية الاتساق من مصدر غير موثوق لا تُعلن verified؛ نتيجة unavailable لا تصدر إيصال تحقق.

## T06 — مصدر سياسة واحد ودقة مالية (2–3 أيام)

**المالك:** Backend؛ تغييرات العقد إن لزمت عند Web3 فقط. **الاعتماديات:** T03. **المتطلبات:** R07.

**Files:** Create `ai-engine/app/schemas/policy.py`, `ai-engine/app/services/policy_service.py`, `ai-engine/app/routes/v2/policies.py`, `ai-engine/tests/test_policy_service.py`; Modify `frontend/src/utils/currency.js`, `contracts/ComplianceRules.sol` للتوثيق/التحقق لا لتغيير الرقم تجارياً.

**Interfaces:** `get_active_policy(institution_id,asset) -> PolicyVersion` مع الحقول §7؛ ETH من getActiveThresholds لا من constants الواجهة؛ عرض النقود يأخذ currency/scale/amount_minor كنص.

- [x] اختبر threshold-1/threshold/threshold+1، amount>2^53، decimal scale خاطئ، policy قديمة، تعطل قراءة المصدر؛ لا تقريب ولا استبدال ب10 ETH.
- [x] شغّل `python -m pytest -q tests/test_policy_service.py` قبل التغيير.
- [x] نفذ int/Decimal في المال وأزل أسعار التحويل الثابتة من قرارات الامتثال؛ نموذج float القائم يظل v1/demo حتى T18 يعزل حساب scoring العددي عن المال الأصلي.
- [x] تحقق أن 9.85 ETH و10,000 ETH لهما نفس التفسير في القراءة والخادم والواجهة، وأن IQD لا يدخل قواعد ETH.
- [x] حدّث ملف سياسة fixture التجريبي ومصدره ثم commit.

**القبول:** لا تقرر أي شاشة أو endpoint institutional باستخدام حد مضمن مخالف للسياسة النشطة.

## T07 — API V2 صارم وعميل مولد (2–4 أيام)

**المالك:** Backend ثم Frontend لعميل العرض. **الاعتماديات:** T05,T06. **المتطلبات:** R06.

**Files:** Create `ai-engine/app/routes/v2/__init__.py`, `ai-engine/app/schemas/common.py`, `scripts/export-openapi.py`, `shared/openapi-v2.json`, `frontend/src/api/generated/schema.d.ts`, `frontend/src/api/client.js`, `ai-engine/tests/test_v2_contracts.py`; Modify `ai-engine/app/main.py`, `frontend/src/utils/aiClient.js`؛ API domain endpoints اللاحقة تنشأ في مهامها لا placeholders ناجحة.

**Interfaces:** تسجيل routes V2 المتاحة فقط؛ errors {code,message,request_id,details}؛ lifecycle health live/ready؛ OpenAPI schema هو المصدر، توليد TS types يستخدمه JS عبر JSDoc/checkJs انتقائي، دون ترحيل شامل إلى TypeScript.

- [x] اختبر exact payloads من الواجهة لـverify/policy/health، رفض الحقول الزائدة/المفقودة 422، والتمييز بين HTTP error وdependency_unavailable وinvalid evidence.
- [x] شغّل من ai-engine `python -m pytest -q tests/test_v2_contracts.py` قبل الإصلاح.
- [x] طبق schemas والتصدير وعميل fetch دون fallback؛ أضف scripts `api:export`, `api:generate`, `api:check` في root package.json؛ قوائم المخططات تنشأ بترتيب ثابت.
- [x] شغّل `npm run api:check`؛ إعادة توليد بلا diff، ثم اختبارات API. وجود نقطة endpoint في الواجهة لا يُعد كافياً دون request/response اختبار فعلي.
- [x] حدّث docs/api-reference.md ووصف v1/demo/v2؛ commit انتقائي.

**القبول:** تغيّر غير متوقع في مخطط API يفشل الفحص الآلي؛ checkAIHealth يستخدم مساراً فعلياً ويتحقق من ML_loaded الفعلي.

## T08 — ABI مولدة وفصل العرض عن التشغيل (3–5 أيام)

**المالك:** Frontend، مالك scripts المولدة DevOps. **الاعتماديات:** T03,T04,T06,T07. **المتطلبات:** R05,R06,R10.

**Files:** Create `scripts/export-contracts.js`, `frontend/src/contracts/generated/`, `frontend/src/config/runtime.js`, `frontend/src/demo/fixtures.js`, `frontend/src/hooks/useAuditEngine.test.jsx`, `frontend/src/utils/aiClient.test.js`, `frontend/vitest.config.js`; Modify `frontend/src/utils/contract.js`, `frontend/src/hooks/useAuditEngine.js`, `frontend/src/App.jsx`, `frontend/package.json` وlockfile بمالك واحد.

**Interfaces:** `APP_MODE=demo|institutional` configuration؛ `getVerifiedDeployment(institutionId)` يفحص chainId/code/address؛ `connectWallet()` لا يرجع محفظة مصطنعة في institutional؛ `OperationResult={status:'confirmed'|'rejected'|'failed',transaction_hash?,error?}`؛ `contracts:export` و`contracts:check` بالجذر.

- [x] اختبر chain خالية تعرض empty، رفض محفظة يبقى rejected، disconnect لا ينشئ معاملة ناجحة، تبديل الحساب يحدث role، تبديل chain يمنع الكتابة، unknown verification لا يعرض علامة خضراء؛ قارئ ABI يطابق بنية الدليل والمقترح الفعلية.
- [x] أضف Vitest/Testing Library بإصدارات متوافقة مع Vite5 بعد تحقق التنفيذ، ثم `npm --prefix frontend test -- --run`؛ أثبت فشل السلوك قبل إصلاحه.
- [x] انقل demo fixtures لمسار منفصل وأزل SUPER_ADMIN الافتراضي وcatch=>current address، وحساب0 من institutional؛ ولّد ABIs من artifacts. استخدم الدور الفعلي حتى T13 يضيف OIDC والربط.
- [x] شغّل root `npm run contracts:check` وfrontend tests/build؛ اختبار local EVM بعناوين deployment حقيقية يقرأ Evidence/Proposal دون deferred decoding errors.
- [x] راجع حالات loading/empty/error/offline باللغة العربية والإنجليزية ثم commit.

**القبول:** الوضع المؤسسي لا يدخل demo بفشل الاتصال؛ كل كتابة تحتاج توقيعاً وتأكيداً واضحين.

## T09 — واجهة موافقات متصلة بالعقود (2–3 أيام)

**المالك:** Frontend. **الاعتماديات:** T03,T08. **المتطلبات:** R02,R03,R05.

**Files:** Modify `frontend/src/components/RoleManagement.jsx`, `frontend/src/hooks/useAuditEngine.js`; Create `frontend/src/hooks/useGovernance.js`, `frontend/src/components/RoleManagement.test.jsx`.

**Interfaces:** `useGovernance()` ينتج proposals/createProposal/approveProposal/executeProposal؛ يدعو ABI T03؛ مصدر proposal.status هو العقد لا عداد محلي. role display من RoleManager ثم هوية T13.

- [x] اختبر عدم السماح بصوت مكرر، عدم مساواة APPROVED بـEXECUTED، فشل signature، اقتراح منتهي، تبديل الحساب، والتحقق من بيانات الفعل قبل توقيعه.
- [x] شغّل frontend `npm test -- --run src/components/RoleManagement.test.jsx` قبل الإصلاح.
- [x] اربط إنشاء/تصويت/تنفيذ بمعاملات منفصلة وتأكيدات؛ أظهر target/actionHash/expiry وتأثير السياسة وسبب الطلب بلغة مفهومة.
- [x] شغّل اختبارات الواجهة وتدفق محلي بأربع محافظ/participant fixtures وثلاثة مشاركين في كل اعتماد؛ تحقق من SoD في العقد حتى مع تجاوز زر الواجهة.
- [x] commit بعد مراجعة توافق بيانات التوقيع والعرض.

**القبول:** لا يمكن زيادة الاعتمادات محلياً أو إعلان التنفيذ قبل حدث مؤكد.

## T10 — نشر محلي متكرر وإعداد runtime صحيح (2–3 أيام)

**المالك:** DevOps بالتنسيق مع Web3. **الاعتماديات:** T02–T09. **المتطلبات:** R05,R16,R18.

**Files:** Modify `scripts/deploy.js`, `docker-compose.yml`, `frontend/Dockerfile`, `frontend/nginx.conf`, `ai-engine/Dockerfile`, `ai-engine/app/config.py`; Create `scripts/verify-deployment.js`, `frontend/public/runtime-config.example.json`, `docs/runbooks/local-start.md`, `.dockerignore`, `frontend/.dockerignore`, `ai-engine/.dockerignore`.

**Interfaces:** manifest {institution_id,chain_id,deployed_at,contract_version,contracts,code_hashes,bootstrap_finalized}؛ deployment job ينتظر node، ينشر ويقفل bootstrap ويصدر runtime config؛ `loadRuntimeConfig()` قبل React render؛ Nginx proxy /api نحو Python بدل browser localhost على جهاز مختلف.

- [x] اختبر بيئة نظيفة بلا artifacts أو عناوين مسبقة، restart node مع بيانات مفقودة، chainId خاطئ، manifest كوده غير مطابق، وعدم نسخ .env/keys إلى images.
- [x] اجعل smoke deployment يفشل أولاً مع Compose الحالي؛ سجّل السبب.
- [x] نفذ npm ci، dependencies مقفلة، ربط RPC المحلي ب127.0.0.1 في demo، healthchecks صحيحة، ومنع institutional عن Hardhat unlocked signers؛ شبكة اختبار مؤسسية محلية بمفاتيح اختبار مستقلة لا مالية.
- [x] شغّل `docker compose config --quiet` ثم clean-stack smoke في مشروع Compose باسم مستقل عن خدمات المستخدم؛ لا تستعمل down -v على بيئة قائمة. تحقّق من UI3005 و/api health وbootstrap.
- [x] سجّل تشغيل/إيقاف/استعادة الـdemo وافصل إعداد institutional التجريبي، ثم commit.

**القبول:** جهاز آخر يستطيع تشغيل demo محلياً دون لصق عناوين؛ تعديل runtime URL يعمل دون rebuild ولا يغيّر الشبكة الموثوقة خفية.

## T11 — CI وضبط الجودة (1–2 يوم)

**المالك:** QA/DevOps. **الاعتماديات:** T07,T08,T10. **المتطلبات:** R06,R16.

**Files:** Create `.github/workflows/verify.yml`, `frontend/eslint.config.js`, `ai-engine/requirements.lock`, `docs/verification/quality-gates.md`; Modify package scripts وrequirements الخاصة بالاختبار بمالك واحد.

**Interfaces:** root `verify:contracts`, `verify:api`, `verify:frontend` تجمع الأوامر المتاحة؛ كل فشل يرجع exit!=0. T11 يشغل smoke النشر الموجود من T10؛ `verify:integration` والبوابة الكاملة تنشآن في T12 بعد وجود runner. فصل متطلبات تشغيل Python عن أدوات الاختبار عند قفلها.

- [x] أضف checks تثبت رفض lint error وschema drift وsecret fixture اصطناعي؛ لا تُضاف قيمة سرية حقيقية لاختبار الفحص.
- [x] نفذ ESLint flat config المتوافق وpin lockfiles؛ سجل الإصدارات المعتمدة وأوامر البيئة Windows/Linux؛ لا ترقية كبرى بدافع إزالة تحذير فقط.
- [x] شغّل npm ci/compile/contracts tests وPython tests وfrontend tests/lint/build والتوليد وsmoke T10 في clean environment على Linux؛ سجل أن التكامل الكامل سيضاف في T12، والتحقق Windows دليل منفصل.
- [x] أرفق تقارير الاختبار والتغطية المقاسة وفحص الاعتماديات؛ finding لا يعالج عبر suppress صامت أو badge نجاح ثابت.
- [x] مراجعة ملف workflow وcommit.

**القبول:** كل بوابة لها أمر قابل للتشغيل محلياً؛ secrets ليست في صور أو artifacts أو logs.

## T12 — اختبار تكامل كامل وبوابة G1 (2–3 أيام)

**المالك:** QA؛ الإصلاح عند صاحب الوحدة. **الاعتماديات:** T01–T11. **المتطلبات:** R01–R07,R10.

**Files:** Create `tests/e2e/trust-flow.spec.js`, `playwright.config.js`, `scripts/run-integration.ps1`, `docs/verification/g1-trust.md`; Modify root `package.json` و`.github/workflows/verify.yml`؛ تحديث test helpers عند الحاجة.

**Interfaces:** runner ينشئ بيئة مؤقتة بأسماء/منافذ خاصة ويحقن manifest وسياق demo/institutional الاختباري؛ لا يمس عقود المستخدم أو بياناته. إضافة npm scripts `test:integration` و`verify:integration` وتفعيلها بوابة CI كاملة بدلاً من الاكتفاء بsmoke T10؛ PowerShell7 runner أو Node runner مكافئ يعمل على Linux/Windows ويمرر خيارات Playwright.

- [x] اكتب flow: submit -> flag -> propose -> two distinct approvals -> execute -> evidence -> verify -> تنزيل verification receipt JSON؛ التقرير المؤسسي الكامل يُختبر في T20. G1 يختبر السلسلة وPython حقيقيين بلا DB بعد، مع file/identity fixtures معلنة؛ G2 يستبدلها بالمصدر الحقيقي.
- [x] اختبر في نفس الرحلة قطع RPC وPython ورفض المحفظة؛ لا confirmed/verified/admin افتراضي، ولا اختفاء أخطاء أو سجل تجريبي بديل.
- [x] شغّل `npm run test:integration` ضد خدمات حقيقية؛ ميّز tests التي تستبدل OIDC بمحاكاة إلى T13 عن blockchain/API التي يجب أن تكون حقيقية.
- [x] أعد اختبارات الرفض T01 بعد الإصلاح، ودوّن أعدادها/نتائجها وأي نقص؛ لا تفتح G1 وفيها Critical/High معرفية غير معالجة.
- [x] راجع diff النهائي في جلسة مستقلة، وحدّث g1-trust.md ثم commit مستهدف.

**القبول:** G1 موثق بأوامر ونتائج وروابط artifacts؛ لا يدعي هوية مؤسسية أو بيانات دائمة قبل G2.
