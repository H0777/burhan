# إصلاح العقود والحوكمة — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** عقود لا تسمح بتجاوز الحوكمة، وتقبل النشر على شبكة EVM قياسية، وتوفر التزامات الأدلة اللازمة للتحقق المستقل.

**Architecture:** RoleManager لهوية مؤسسية ثابتة، وMultiSigApproval منسق القرار الوحيد بعد bootstrap. تبقى Evidence V2 دون تغيير مع التزام منفصل لبيان المصدر في ForensicTrail الجديد.

**Tech Stack:** Solidity 0.8.20، Hardhat 2، ethers، optimizer runs=200.

**Spec:** [§3–7 من التصميم](../specs/2026-10-23-verified-remediation-design.md).

## Global Constraints

- موافقتان مستقلتان غير المقترح؛ أربعة مشاركين مصوتين فريدين عند bootstrap؛ TTL=259,200 ثانية.
- تأخير 86,400 ثانية للسياسات والأدوار ومنح صلاحيات الخدمة؛ إلغاء writer/recorder بعد النصاب بلا تأخير.
- deployed bytecode<=24,000 بايت؛ allowUnlimitedContractSize=false؛ contract_version=2.1.0.
- لا تغيير Evidence V2 أو مجاله، ولا ترحيل governance عبر call عام، ولا proxy جديد.
- الملفات المشتركة والملفات المولدة لها مالك واحد كما في [الخارطة](2026-10-23-remediation-roadmap.md).

## Review Focus

1. تصويت من محفظتين للشخص نفسه — R02 يمنع ذلك بهوية ثابتة ومحفظة فعالة واحدة.
2. انتهاء الصلاحية أو إلغاء الدور بعد التصويت — R03 يعيد الفحص وقت التنفيذ.
3. تغيير نوع المقترح لإخفاء selector حساس — R03 يرفض الهدف/الفعل غير المتطابق.
4. إنذار AuditEngine الآلي دون مفتاح توقيع خارجي — R03 يبقيه chain_generated_unattested دون كسر المعاملة.
5. غياب مشارك أو تدوير كاتب مخترق — R02 يختبر النصاب وR03 يسمح بإلغاء ضيق فوري بعد النصاب.

## R01 — إزالة مدخل الاختبار العام

**السبب:** دالة testSetGeneration تغير جيلاً أمنياً دون صلاحية، فتفسد صلاحية الأصوات.

**الملفات:** تعديل contracts/access/RoleManager.sol وtest/RoleManager.test.js وأي اختبار يستدعي الدالة داخل test/security/ObservedRegressions.test.js. إنشاء test/security/NoTestBackdoor.test.js، وcontracts/test/RoleManagerHarness.sol فقط إذا احتاج اختبار اصطناعي لتغيير الجيل. توليد ABI عبر scripts/export-contracts.js.

**الواجهات:** حذف testSetGeneration(address,uint256) من عقد الإنتاج. تبقى getGeneration(address)->uint256 وgetParticipant(address)->(bytes32,uint256,Role,bool). harness لا يدخل قائمة عقود النشر أو التصدير.

- [ ] أضف outsider_cannot_call_generation_setter: ابن calldata للتوقيع المحذوف، نادِه من عنوان خارج النظام، وتوقع revert وgetGeneration(auditor)==before. أضف production_abi_has_no_test_mutator ليؤكد غياب الاسم من ABI المترجم والمصدّر.
- [ ] شغل npx hardhat test test/security/NoTestBackdoor.test.js؛ يجب أن يفشل على النسخة الحالية بسبب نجاح النداء أو وجود الدالة، لا بسبب fixture معطلة.
- [ ] احذف الدالة؛ اختبر الأجيال من خلال assign/revoke/rotate الحقيقية، واحصر التلاعب الاصطناعي في harness غير منشور.
- [ ] شغل npm run compile ثم الاختبار السابق وnpx hardhat test test/RoleManager.test.js، ثم npm run contracts:export وnpm run contracts:check؛ المتوقع exit=0 وغياب الدالة من كل ABI إنتاجي.
- [ ] راجع git diff وأثبت فصل harness عن scripts/deploy.js؛ سجل الدليل في docs/verification/remediation/R01.md واحفظ commit خاصاً بهذه الملفات فقط.

## R02 — هوية المشارك وتدوير المحفظة وbootstrap

**الاعتماد:** R01. **المالك:** العقود؛ تعديل الملفات المشتركة متسلسل.

**الملفات:** تعديل contracts/access/RoleManager.sol وcontracts/access/MultiSigApproval.sol وcontracts/interfaces/IRoleManager.sol وtest/RoleManager.test.js وtest/MultiSigApproval.test.js. إنشاء test/security/ParticipantIdentity.test.js. تعديل scripts/deploy.js هنا لتمرير roster fixture فقط؛ تحديثه النهائي في R04.

**الواجهات الناتجة:**

    enrollParticipant(bytes32 participantId,address wallet,Role role,string reason)
    rotateParticipantWallet(bytes32 participantId,address newWallet,string reason)
    getActiveWallet(bytes32 participantId) -> address
    countEligibleParticipants() -> uint256
    bootstrapParticipants(bytes32[] ids,address[] wallets,uint8[] roles,string[] reasons)
    getParticipant(address wallet) -> (bytes32 participantId,uint256 generation,Role role,bool active)

توابع enrollment/rotation governance-only؛ assignRole لا ينشئ هوية مشتقة من address، بل يتطلب enrollment. يحتفظ العنوان الملغى بربطه التاريخي ولا يمكن إعادة نسبته لشخص آخر. جيل participant يزداد لكل grant/revoke/rotation وتصدر الأحداث بهوية المشارك والجيل؛ محفظة واحدة نشطة لكل هوية. roster معرفاته عشوائية مؤسسية غير دالة على أسماء الأشخاص، وتحفظ علاقة الإنسان بالمعرف في العضوية خارج السلسلة.

- [ ] أضف tests: duplicate_participant_rejected، duplicate_wallet_rejected، zero_id_rejected؛ جميعها revert. أضف rotation_invalidates_old_wallet: العنوان القديم inactive، الجديد له participantId نفسه، generation_after>generation_before.
- [ ] أضف bootstrap_requires_four_eligible_identities: ثلاثة AUDITOR ومشغل لا تكفي؛ أربعة مؤهلين تكفي؛ بصوت المقترح نفسه لا يتحقق النصاب، وبغياب واحد يمكن لثلاثة متبقين تقديم مقترح والحصول على موافقتين. لا تفترض توافر النصاب إذا كان اثنان أطراف القضية.
- [ ] شغل npx hardhat test test/security/ParticipantIdentity.test.js؛ المتوقع فشل على enrollment/rotation والنصاب الحالي.
- [ ] نفذ الواجهات، وألغِ دور deployer المؤقت عند finalizeBootstrap ما لم يكن ضمن roster صراحة. افحص اكتمال التكامل وallowlists قبل محو bootstrapAuthority نهائياً، وامنع إعادة configure/bootstrap بعد الإنهاء.
- [ ] شغل الاختبار السابق ثم npx hardhat test test/RoleManager.test.js test/MultiSigApproval.test.js؛ راجع أن تجربة alias بمحفظة قديمة/جديدة لا تضيف صوتين وأن regrant لا يعيد جيلاً قديماً.
- [ ] سجل tuple serialization والأحداث الجديدة ونتيجة الاختبارات في R02.md، ثم راجع الفرق واحفظ commit محدوداً. سلّم الواجهات إلى R03 وR10 قبل استخدامهما.

## R03 — توحيد الحوكمة وربط بيانات التنفيذ وإضافة التزام البيان

**الاعتماد:** R02. **المالك:** العقود. هذه حزمة حساسة تتطلب مراجعة ثانية لفرقها النهائي.

**الملفات:** تعديل contracts/AuditEngine.sol وcontracts/access/MultiSigApproval.sol وcontracts/forensics/ForensicTrail.sol وcontracts/forensics/InsiderActivityLog.sol وcontracts/interfaces/IAuditEngine.sol وIForensicTrail.sol. تعديل test/security/GovernanceExecution.test.js وObservedRegressions.test.js وtest/AuditEngineIntegration.test.js وtest/ForensicTrail.test.js. إنشاء test/security/TimelockAndActionBinding.test.js وtest/forensics/ManifestCommitment.test.js.

**واجهات القرار:**

    createProposal(ProposalType proposalType,address target,bytes data,string description) -> uint256
    approveProposal(uint256 proposalId)
    executeProposal(uint256 proposalId)
    executePolicyChange(PolicyProfile policy) // AuditEngine, governance-only
    executeCustomThresholds(uint256 largeThreshold,uint256 dailyLimit,
                            uint256 maxDaily,uint256 maxSingle,uint256 kycThreshold)
    executeOverrideWarning(uint256 txId,address sender,address receiver,string justification)
    executeEmergencyUnpause(uint256 expectedEpoch)

الـselector مسموح فقط حسب جدول التصميم. تُزال الواجهات القديمة overrideWarning وoverrideWarningWithMultiSig وemergencyUnpause وsetMultiSigOverrideEnforcement وsetPolicyTimelockDelay وproposePolicyChange وproposeCustomThresholds وexecutePolicyChangeWithMultiSig وcancelPolicyChange وsetPolicy وsetCustomThresholds. executePolicyChange الجديد لا يقرأ proposal موازياً في AuditEngine؛ القرار والوقت في المنسق وحده. يبقى emergencyPause فورياً للدور المسموح مع زيادة pauseEpoch.

قائمة SYSTEM_CONFIG تشمل setEvidenceWriter وsetRecorder وsetBusinessHours فقط. تفك data بالأنواع الصحيحة وتفحص طولها وإعادة ترميزها لمنع trailing garbage؛ false للإلغاء يعطي notBefore=createdAt، وtrue للمنح يعطي +86,400. العناوين المسجلة وقت configure هي الأهداف الوحيدة. لا يضاف setGovernance إلى القائمة.

**واجهات ForensicTrail:**

    submitEvidenceAttested(uint256 incidentId,bytes32 requestId,bytes32 typeHash,
                           bytes32 descriptionHash,bytes32 fileSha256,
                           bytes32 manifestDigest) -> uint256 evidenceId
    getManifestDigest(bytes32 requestId) -> bytes32
    EvidenceManifestAnchored(bytes32 indexed requestId,uint256 indexed evidenceId,bytes32 manifestDigest)
    createIncidentForCase(bytes32 caseReferenceHash,bytes32 titleHash,bytes32 severityHash) -> uint256
    getIncidentByCaseReference(bytes32 caseReferenceHash) -> uint256

المراجع مشتركة على مستوى العقد المؤسسي؛ يحتفظ أول مرجع بmetadata ومقدمه، وإعادة الطلب من كاتب آخر لا تستولي عليه. يعتبر requestId نفسه مع manifestDigest آخر تعارضاً. لا دالة backfill للالتزام. يبقى submitEvidence القديم لأثر النظام الآلي غير الموثق بخدمة الملفات، ويصنفه R07 صراحة.

- [ ] اكتب admin_cannot_bypass_after_bootstrap: calls قديمة من SUPER_ADMIN تفشل، ولا تتغير السياسة أو FLAGGED. اكتب forbidden_type_selector_target يرفض ROLE_CHANGE مع calldata تجاوز، وعقداً عشوائياً، وsetGovernance، وحقول sender/receiver لا تطابق التحويل.
- [ ] اكتب timelock_boundaries: عند created+86,399 يفشل؛ عند +86,400 ينجح مرة واحدة؛ عند expiresAt يفشل وفق قاعدة now>=expiresAt. stale_generation_after_approval وproposer_rotation وparticipant_is_transaction_party تفشل دون تعديل الحالة.
- [ ] اكتب emergency_epoch_replay: مقترح فك إيقاف للـepoch السابق لا يفك pause لاحقاً. writer_revocation_immediate_but_grant_delayed يثبت فارق 0/86,400 مع الموافقتين في الحالتين.
- [ ] اكتب manifest_is_bound_to_request: digest صفر مرفوض، إعادة نفس الطلب لا تزيد count، digest مختلف مرفوض، وevent/lookup يعيدان digest الصحيح. case_reference_is_idempotent يثبت incident واحداً لنفس المرجع وتعارض metadata. automated_alarm_still_records يثبت عدم كسر AuditEngine ومسار إنذاره القديم.
- [ ] شغل npx hardhat test test/security/TimelockAndActionBinding.test.js test/forensics/ManifestCommitment.test.js؛ سجل فشل السلوك الحالي.
- [ ] نفذ جدول الأفعال المغلق والتأخير وفحص participant/generation عند التصويت والتنفيذ. احذف مسارات الإدارة الموازية، واجعل التنفيذ المستهدف atomic؛ revert الهدف لا يترك المقترح EXECUTED ولا يستهلكه نهائياً.
- [ ] شغل npm run test:contracts؛ حدّث اختبارات متطلبات السلوك القديم لتطلب منع الـbypass، لا تحذف regression لتجاوز الفشل. شغل node --test shared/tests/evidence-hash.test.mjs وnpx hardhat test test/forensics/EvidenceHashing.test.js لإثبات بقاء hash V2.
- [ ] راجع فرق التوابع الخارجية والموديفيرات منفصلاً عن الاختبارات، وسجل كل selector وهدفه وتأخيره في R03.md، ثم commit محصور.

## R04 — حجم العقد والنشر القياسي وسجل النشر

**الاعتماد:** R03. **المالك:** العقود/التكامل؛ بعد هذه المهمة تسلم ملفات التشغيل إلى R14.

**الملفات:** تعديل hardhat.config.js وscripts/deploy.js وscripts/verify-deployment.js وscripts/check-contracts.js. إنشاء scripts/check-contract-size.js وtest/security/DeploymentInvariants.test.js وdeployments/deployment-manifest.schema.json. تعديل contracts/AuditEngine.sol أو إنشاء contracts/libraries/AuditPolicyMath.sol فقط إذا لم يكف حذف المسارات القديمة. توليد الملفات التي يحددها scripts/export-contracts.js؛ تحديث manifest محلياً دون تضمين مفاتيح.

**الواجهة:** check-contract-size يقرأ deployedBytecode من artifact حديث، يرفض unlinked placeholders أو حجم>24,000، ويخرج JSON {contract,compiler,optimizer_runs,runtime_bytes,budget,passed}. verify-deployment يفحص chainId/codehash/governance/bootstrap/roster/writer/recorder/TTL/delays فعلياً عبر RPC، ويفشل عند غياب حقل مطلوب. manifest_version=3، ويحتوي حقول DeploymentBinding المحددة في التصميم؛ المفاتيح الخاصة ليست حقولاً صالحة.

- [ ] أضف size_gate_rejects_24577_and_24001 ويقبل 24,000؛ لا تحسب constructor/init bytecode. أضف fresh_standard_deployment لكل العقود دون unlimited size، وmanifest_wrong_chain_or_codehash_is_rejected.
- [ ] سجل حجم build جديد بـnpm run compile ثم node scripts/check-contract-size.js. إن نجح بعد R03 فهذا PASS_AFTER_UPSTREAM_FIX مع حفظ دليل رفض النشر التاريخي؛ لا تصطنع اختباراً أحمر بتوسيع الكود.
- [ ] اضبط allowUnlimitedContractSize=false؛ إذا بقي الحجم مرتفعاً، استخرج حسابات نقية محددة من AuditEngine إلى مكتبة مرتبطة لا تتحكم بstorage أو authorization. حافظ على سلوك السياسة ووحدات ETH/wei واختبر الحدود نفسها.
- [ ] عدل النشر لـTTL=72 ساعة وroster الأربع وإيداع العناوين/code hashes عند الإنهاء. اكتب manifest فقط بعد نجاح جميع الخطوات باستخدام temp+atomic replace؛ فشل bootstrap لا يترك manifest صالحاً.
- [ ] شغل npm run compile ثم node scripts/check-contract-size.js ثم npx hardhat run scripts/deploy.js --network hardhat ثم npm run contracts:export وnpm run contracts:check ثم npm run test:contracts؛ جميعها exit=0.
- [ ] على عقدة اختبار مستقلة مطابقة للحد القياسي شغل npm run deploy:local ثم npm run deploy:verify؛ عين RPC لهذا الاختبار صراحة ولا تستخدم شبكة خارجية. سجل block/hash وruntime sizes وmanifest digest في R04.md.
- [ ] راجع الفرق والمخرجات المولدة، واحفظ commit محصوراً. الحد الأعلى للشبكة ليس مبرراً لتجاوز ميزانية 24,000 دون تعديل تصميم موثق.

## التسليم

RG1 لا ينجح باجتياز اختبارات على ABI قديم أو artifacts دون compile. سلّم R05–R08 حقول manifest والأحداث وواجهات attested/case reference؛ سلّم R10 tuple الهوية والأجيال؛ سلّم R13 ABI الجديد وتعريف legacy_read_only.
