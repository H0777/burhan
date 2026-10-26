# إصلاح الأدلة والتوقيع والتثبيت — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** لا تنتج المنظومة أو أداة التحقق المستقلة نتيجة رسمية ناجحة من ملف مفقود أو توقيع مزور أو مرساة مصطنعة.

**Architecture:** بيان مصدر موقع قبل outbox، والتزام ببصمة البيان والتوقيع على ForensicTrail، ومحقق يستخدم ملفات مخزنة ولقطة سلسلة ثابتة. التقرير وحزمة التصدير يستهلكان نتيجة التحقق المحفوظة نفسها.

**Tech Stack:** Python/FastAPI/SQLAlchemy، cryptography/Ed25519/AES-GCM، PostgreSQL 16، EVM RPC وEvidence V2.

**Spec:** [§5–7 من التصميم](../specs/2026-10-23-verified-remediation-design.md).

## Global Constraints

- لا fallback مفبرك في المسار المؤسسي؛ network error=unavailable، mismatch مثبت=invalid.
- لا تغيير Evidence V2؛ الالتزام الجديد يحمي canonical signed envelope الذي يتضمن التوقيع نفسه.
- domains: AML_SERVICE_MANIFEST_V1 وAML_DOSSIER_V1 وAML_BACKUP_V1؛ مفاتيح خاصة خارج Git وZIP وlogs.
- ملف<=25*1024*1024 بايت؛ حزمة<=512MiB و200 ملف دليل و1,000 عضو؛ لا EVIDENCE-STUB.
- canonical JSON: UTF-8، sort_keys=True، separators=(",",":")، ensure_ascii=False، allow_nan=False؛ لا floats أو duplicate keys.
- تعديلات models.py وmigrations ينفذها مالك DB وفق ترتيب [الخارطة](2026-10-23-remediation-roadmap.md).

## Review Focus

1. تبديل مفتاح موثوق بواحد مرفق داخل ZIP — R05، R09 يرفضان الثقة الذاتية.
2. إلغاء الكاتب بعد إضافة دليل في البلوك نفسه — R07 يعيد ترتيب الأحداث قبل الإضافة.
3. قتل العامل بعد بث المعاملة وقبل commit — R08 يسترد نفس tx/request دون تكرار.
4. رفعان متزامنان لنفس object version — R06 يقبل واحداً فقط ويحفظ البايتات الأصلية.
5. لقطة سابقة يليها دليل جديد — R07/R09 يثبتان اللقطة الأصلية دون إلزامها برأس السلسلة الحالي.

## R05 — مفاتيح وتوقيع وسجل ثقة قابل للاختبار

**الاعتماد:** R00. **المالك:** الأدلة/الأمن؛ dependency edits عند قائد التكامل فقط.

**الملفات:** إنشاء shared/python/evidence_crypto.py للـcanonical/signature/trust primitives المشتركة، وai-engine/app/security/signing.py وkey_provider.py وtrust_registry.py كواجهات للخادم، وshared/schemas/service-manifest-v1.schema.json وtrust-registry-v1.schema.json وshared/fixtures/signatures-v1.json. إنشاء ai-engine/tests/test_signing.py. تعديل ai-engine/requirements.txt وrequirements.lock فقط لتثبيت cryptography متوافقاً مع runtime الحالي إذا لم يكن مثبتاً فعلاً؛ لا كتابة crypto بدائي يدوي. إنشاء docs/runbooks/key-management.md.

**الواجهات:**

    canonical_bytes(body: dict) -> bytes
    Signer.sign(institution_id: str, domain: str, body: dict) -> SignedEnvelope
    Verifier.verify(domain: str, envelope: SignedEnvelope,
                    registry: TrustRegistry, trusted_time: datetime | None) -> SignatureResult
    KeyProvider.get_signing_key(institution_id: str, key_id: str) -> Ed25519PrivateKey
    KeyProvider.wrap_data_key(institution_id: str, dek: bytes) -> WrappedKey
    KeyProvider.unwrap_data_key(institution_id: str, wrapped: WrappedKey) -> bytes

SignedEnvelope={body,algorithm:"Ed25519",signature:base64}؛ body يحتوي institution_id/key_id/schema_version. SignatureResult.status=verified|invalid|unavailable وreason ثابت. الخادم وCLI يستخدمان shared/python/evidence_crypto.py نفسه؛ تحميله من مسار ثابت نسبة إلى التوزيعة، لا مسار يختاره ZIP. تبنى توزيعة المحقق من script+shared module+schemas+ABI دون app أو DB، وتثبت cryptography من lockfile. مؤقتاً يستعمل التشغيل المحلي ملفات secret mounted read-only خارج المستودع، مملوكة لحساب الخدمة، ولا يعيد المفتاح داخل response. واجهة المزود تعزل تبديلها لاحقاً بخدمة مفاتيح دون شراء خدمة ضمن هذه الخطة.

- [ ] اكتب tests: tampered_byte_invalid، wrong_institution_key_invalid، wrong_domain_invalid، missing_registry_unavailable، embedded_key_not_trusted، duplicate_json_key_rejected، float_rejected. تثبت fixtures أن ترتيب مفاتيح JSON لا يغير canonical digest وأن نصاً عربياً لا يتلف.
- [ ] أضف retired_key_requires_trusted_time وcompromised_key_rejects_from_invalid_from؛ تاريخ صادر من ZIP وحده ليس trusted_time، وغياب invalid_from لمفتاح compromised يبطل جميع تواقيعه. اختبر انتهاء الصلاحية والحدود بالثانية.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/test_signing.py؛ المتوقع فشل قبل إنشاء الواجهات، مع توثيق اختبار التوقيع المزور التاريخي في R05.md.
- [ ] نفذ التوقيع/التحقق بالمكتبة وسجل الثقة الخارجي، وسياسة fail-closed للمفتاح الناقص؛ أنشئ fixture مفاتيح اختبار واضحة فقط ولا تدرج مفتاح مؤسسة حقيقي.
- [ ] شغل الاختبار السابق، وأثبت أن تغيير signature نفسه يغير digest للـenvelope حتى إذا لم يتغير body.
- [ ] راجع مواضع logging والأخطاء وملفات Git المتغيرة بحثاً عن مفاتيح؛ سجل schema/fixtures/التحقق، ثم commit محصور. سلّم الواجهات إلى R06/R07/R09/R16.

## R06 — مخزن مشفر ومنع overwrite وبيان منشأ موقع

**الاعتماد:** R05، R11. **المالك:** الأدلة؛ migration/model عند مهندس DB.

**الملفات:** تعديل ai-engine/app/services/evidence_store.py وevidence_broker.py وrepositories/evidence_repository.py. إنشاء ai-engine/app/services/encrypted_object.py وai-engine/tests/integration/test_evidence_immutability.py وtest_evidence_encryption.py. تحديث tests/integration/test_evidence_store.py وtest_evidence_delivery.py. إضافة migration 0002_evidence_crypto عبر مالك DB.

**التغييرات المخزنة:** evidence_objects تضيف ما ينقصها من storage_format، encryption_key_id، wrapped_dek، nonce، auth_tag، manifest_envelope_json، manifest_digest؛ وتحافظ على object_version الحالي وunique(institution_id,evidence_id,object_version) بعد فحص المخطط. لا تحفظ مفتاح DEK مكشوفاً. manifest_digest هو SHA-256 للـenvelope canonical لا للـbody وحده.

**الواجهات:** حافظ على EvidenceStore.put(...) -> StoredEvidence وopen(...) -> (bytes,metadata) للتوافق مع الاستدعاءات الحالية ضمن حد 25MiB. أضف open_verified_stream(institution_id,evidence_id,object_version)->BinaryIO للقراءة الكبيرة/التصدير؛ لا يحرر plaintext للمستدعي قبل نجاح GCM tag، ويمكن استعمال staging محمي مؤقتاً. broker ينتج SignedEnvelope من R05 ويخزن metadata/outbox في معاملة واحدة.

- [ ] اكتب same_version_two_writers_only_one_success مع عمليتين مستقلتين؛ البايتات النهائية تخص الفائز فقط ولا تتداخل staging files. أضف crash_before_publish_leaves_no_readable_object، missing_metadata_not_accepted، tampered_ciphertext_or_tag_invalid.
- [ ] اختبر 25*1024*1024 مقبول و+1 مرفوض دون بقاء ملف نهائي. أضف Windows_unicode_display_name مع اسم عربي محفوظ للعرض ومعرف داخلي آمن؛ وpath_prefix_sibling وsymlink_escape وmetadata_filename_traversal كلها ترفض.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_evidence_immutability.py ai-engine/tests/integration/test_evidence_encryption.py؛ يجب إثبات الفشل الفعلي قبل الإصلاح.
- [ ] نفذ AES-256-GCM وAAD يربط المؤسسة والدليل والنسخة، ومفتاح DEK عشوائياً لكل كائن. انشر مجلد نسخة مكتملة بطريقة no-replace، باسم staging فريد وmarker مكتمل؛ لا تعتمد exists ثم rename قابل للاستبدال. المسار يثبت relative_to للجذر ويرفض الروابط.
- [ ] اجعل get_signed_manifest ينتج توقيعاً حقيقياً لا digest اسمه توقيع. خزّن signed envelope قبل outbox؛ في فشل DB احذف staging غير المنشور فقط، واجمع orphan objects غير المرتبطة لاحقاً وفق retention دون حذف ملف مثبت.
- [ ] افحص انتقال الملفات القديمة: تبقى legacy_plaintext_read_only وlegacy_unattested؛ لا تحويل صامت أو توقيع بأثر رجعي. تحويل مشفر لاحق يحفظ hash الأصلي وسجل migration ولا يغيّر مستوى provenance.
- [ ] شغل الاختبارات الجديدة وtest_evidence_store.py وtest_evidence_delivery.py؛ اختبر rotation بكتابة v2 بالمفتاح الجديد وقراءة v1 بالمفتاح السابق، ورفض فكها بمفتاح مؤسسة ثانية. سجل R06.md وcommit محصوراً.

## R07 — محقق أدلة حقيقي وAPI V3 ولقطات

**الاعتماد:** R04، R06، R10. **المالك:** السلسلة/الأدلة؛ schema generation عند التكامل.

**الملفات:** تعديل ai-engine/app/services/evm_rpc_client.py وchain_registry.py وevidence_verifier.py وapp/schemas/evidence.py وapp/routes/v2/evidence.py. إنشاء app/routes/v3/evidence.py وapp/services/anchor_reader.py وai-engine/tests/integration/test_evidence_verification_v3.py وtest_chain_snapshot.py. تحديث ai-engine/tests/test_evidence_verifier.py. إضافة migration 0003_verification_snapshots، وتسجيل router في main.py بواسطة مالكه.

**الواجهات:**

    ChainRegistry.resolve(institution_id: str,deployment_id: str | None) -> DeploymentBinding
    AnchorReader.read_incident(binding: DeploymentBinding,incident_id: int,
                               snapshot: ChainSnapshot) -> AnchoredIncident
    AnchorReader.writer_authorized_at(binding,writer,event_position: EventPosition) -> bool
    verify_case_evidence(session: Session,identity: Identity,request: VerifyEvidenceRequest,
                         reader: AnchorReader,store: EvidenceStore,verifier: Verifier)
                         -> VerificationResult

ChainSnapshot={id,chain_id,block_number:int,block_hash:str,confirmation_depth:int}؛ EventPosition={block_number,transaction_index,log_index}. AnchoredIncident يحتوي الإدخالات الحقيقية وrequestIds وmanifestDigests ومواقع أحداثها، لا object placeholders. قيود snapshot/evidence تربط المؤسسة والنسخة والتقرير. تعريف request/result وحالات HTTP في §5 من التصميم هو العقد النهائي.

- [ ] أضف fabricated_entries_same_count_never_verify: عدد متساوٍ ومحتوى مختلف لا يمر. أضف wrong_contract، missing_codehash، missing_rpc_method، missing_file، tampered_file، unsigned_manifest، swapped_case، wrong_institution؛ لا حالة منها verified.
- [ ] أضف no_identity_401 وcross_tenant_404 وclient_entries_field_422 وv2_institutional_returns_410؛ لا تجاوز لإذن القضية عبر evidence_ids.
- [ ] أضف all_reads_use_same_block، append_preserves_snapshot، reorg_marks_unavailable، current_head_not_snapshot_head. أضف writer_add_then_revoke_same_block وrevoke_then_submit_same_block وgrant_after_submit؛ الترتيب قبل event هو الفيصل، لا end-of-block state.
- [ ] أضف manifest_signature_changed_after_anchor_invalid وretired_service_key_anchor_time_proven وhistorical_logs_unavailable؛ يتطابق SHA-256 للـenvelope نفسه مع getManifestDigest/الحدث. صفر أدلة في الطلب يرفض 422؛ سلسلة فارغة لا تعني وجود دليل متحقق.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_evidence_verification_v3.py ai-engine/tests/integration/test_chain_snapshot.py؛ سجل الفشل المقصود.
- [ ] نفذ قراءة ABI الفعلية والربط المؤسسي وblock tag وwriter event replay منذ deployed_at_block، مع تحقق code hash عند اللقطة وإعادة فحص block_hash. لا تستخدم القيم الافتراضية أو current writer allowlist بدل التاريخ.
- [ ] نفذ hashing/الملف/التوقيع والـmanifest commitment وحفظ VerificationSnapshot. صنّف أثر النظام غير الموقع chain_generated_unattested، وغياب المصدر التاريخي legacy_unattested دون تزوير حالة verified.
- [ ] شغل الاختبارات الجديدة وtest_evidence_verifier.py وtest_evidence_hashing.py ثم npm run api:export وnpm run api:check. مخرجات V3 الجديدة يضيفها R13/R20 إلى التوليد الموجود دون محو OpenAPI V2.
- [ ] نفذ تكامل فعلي مع عقود R04 على RPC محلي وPostgreSQL، وأثبت اختلاف contract code hash وتعطل RPC. سجل R07.md وراجع الفرق واحفظ commit محدوداً.

## R08 — تسليم outbox ومعاملات فعلية واسترداد التعطل

**الاعتماد:** R07، R11. **المالك:** الخلفية/السلسلة؛ لا تشغيل افتراضي في طلب HTTP.

**الملفات:** تعديل app/workers/evidence_anchor.py وindexer.py وrepositories/outbox_repository.py وevidence_repository.py وservices/evm_rpc_client.py. إنشاء app/workers/runner.py وapp/services/chain_sender.py وai-engine/tests/integration/test_anchor_crash_recovery.py وtest_outbox_claims_postgres.py وtest_sender_nonce.py. تحديث test_indexer_recovery.py وtest_evidence_delivery.py. إضافة migration 0004_outbox_delivery.

**الحقول:** outbox: lease_owner/token، lease_expires_at، next_attempt_at، last_error، status، attempts. chain_submissions: institution_id، chain_id، signer_address، nonce، protected_raw_tx، tx_hash، request_id، receipt_block/hash، status؛ unique(chain_id,signer_address,nonce)، unique(institution_id,request_id,submission_kind). case_incident_mappings: institution_id+deployment_id+case_id فريدة مع case_reference_hash وincident_id. heartbeat لكل عامل.

**الواجهات:**

    claim_batch(session,institution_id:str,worker_id:str,now:datetime,limit:int=20) -> list[Outbox]
    renew_lease(session,outbox_id:str,lease_token:str,now:datetime) -> bool
    ChainSender.prepare_and_persist(session,binding,call,request_id:str) -> ChainSubmission
    ChainSender.broadcast(submission: ChainSubmission) -> str
    ChainSender.reconcile(submission: ChainSubmission) -> SubmissionState
    python -m app.workers.runner anchor
    python -m app.workers.runner indexer

لا optional RPC في constructor المؤسسي. read + send adapters تستعمل registry binding نفسه. readEvidenceByRequestId وcase reference يسبقان إعادة الإرسال. وقت الانتظار ليس إخفاق استدلال أو ذريعة لصنع block_hash.

- [ ] اكتب no_rpc_never_anchors، two_workers_claim_disjoint، expired_lease_reclaimed، wrong_owner_cannot_complete. اختبر lease=60s وتجديد 20s وإخفاق 5 محاولات وفق فواصل 5/30/120/600/1800؛ التوقيت عبر clock محقون لا sleep حقيقي.
- [ ] اكتب crash_after_claim، after_signed_tx_commit، after_broadcast_before_receipt، after_receipt_before_db_commit؛ بعد restart يوجد incident واحد وentry واحد وCOMPLETED واحد، ونفس tx_hash/nonce عند إعادة البث.
- [ ] اكتب two_tenants_two_incidents_not_one وrequest_payload_conflict_is_dead وreceipt_status_zero_not_anchored وreceipt_reorg_returns_submitted وnonce_consumed_externally_pauses_signer.
- [ ] شغل الاختبارات الجديدة على PostgreSQL حقيقي؛ SQLite/mock لا يغلق SKIP LOCKED أو nonce concurrency. سجل أول فشل سلوكي.
- [ ] نفذ claim/leases وفصل commit القصير عن I/O، وowner-token conditional updates، وقفل advisory per chain+signer. احفظ raw transaction قبل البث، ولا تحفظ مفتاح المرسل في DB أو logs.
- [ ] نفذ pending nonce reconciliation، وcase-reference idempotent creation، وsubmitEvidenceAttested بالـmanifestDigest المخزن. SUBMITTED لا يستنفد retry لكون التأكيد بطيئاً؛ يستمر reconcile. بعد 300s يُوقف إرسال جديد للمرسل وتبقى المراقبة، ولا automatic fee replacement.
- [ ] نفذ runner مع graceful shutdown يتوقف عن claim ويترك lease قابلاً للاسترداد. قائمة المؤسسات من registry موثوق، ويضبط tenant context لكل دورة بدلاً من قراءة كل outbox دون سياق. indexer يعالج reorg/checkpoint والقيود الفريدة ويدون heartbeat دون حذف الدليل الأصلي.
- [ ] شغل الاختبارات الجديدة وtest_indexer_recovery.py وtest_evidence_delivery.py؛ ثم اقتل عامل الحاوية في اختبار RPC فعلي وأعد تشغيله. سجل block/entry/request/lease IDs في R08.md دون أسرار، ثم commit ومراجعة فرق حساسة.

## R09 — التقارير والتصدير والتحقق المستقل

**الاعتماد:** R05، R07، R08، R12. **المالك:** الأدلة/التقارير.

**الملفات:** تعديل ai-engine/app/services/report_service.py وevidence_export.py وapp/schemas/report.py وscripts/verify-evidence-export.py. إنشاء shared/schemas/dossier-manifest-v1.schema.json وai-engine/tests/integration/test_export_signature.py وtest_export_inventory.py. تحديث test_report_provenance.py وtest_forensic_report.py وdocs/runbooks/evidence-verification.md.

**الواجهات:** export_case_report(session,identity,case_id:str,snapshot_id:str)->Path يقرأ لقطة R07، ولا يستنتج VERIFIED من ANCHORED. CLI:

    python scripts/verify-evidence-export.py dossier.zip --registry trusted-registry.json
    python scripts/verify-evidence-export.py dossier.zip --registry trusted-registry.json --online --rpc-url http://127.0.0.1:8545

JSON output: bundle_status، anchor_status، reasons، checked_files، snapshot_id؛ exit codes 0/1/2 كما في التصميم. الأداة تستعمل cryptography وتقرأ العقود من schema/ABI موزع مع الإصدار؛ لا تستورد خادم API أو DB لإثبات الاستقلال. --online يقبل RPC مطابقاً للسلسلة المسجلة، ولا يتبع URL داخل ZIP.

- [ ] أضف fabricated_signature_invalid باستعمال algorithm=none وINVALID-NO-PRIVATE-KEY كما في المراجعة؛ missing_registry_unavailable؛ report_markdown_byte_change_invalid؛ missing_file_invalid؛ stub_invalid؛ extra_zip_member_invalid؛ checksums_omitting_file_cannot_hide_it.
- [ ] أضف duplicate_path، case_insensitive_collision، absolute_path، parent_traversal، symlink_member، expanded_size_limit، file_count_limit، duplicate_json_keys؛ يرفض قبل استخراج أي ملف. اختبر الحزمة عند الحدود المحددة في التصميم.
- [ ] أضف offline_bundle_does_not_claim_chain وonline_rpc_failure_unavailable وretired_dossier_key_without_external_checkpoint_unavailable. أضف export_snapshot_survives_later_append وreorg_invalidates_anchor_claim.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_export_signature.py ai-engine/tests/integration/test_export_inventory.py؛ سجل رفض الأداة الحالية للتجربة غير الصحيح/قبولها المخطئ قبل إصلاحها.
- [ ] نفذ inventory كامل وتوقيع AML_DOSSIER_V1، وضم بيانات التحقق والبيان الموقع والملفات الحقيقية؛ إذا نقص ملف امنع إنشاء الحزمة بدلاً من stub. لا تضم manifest/signature نفسهما إلى inventory التدويري.
- [ ] اربط التقرير بـVerificationSnapshot وpolicy/model/version/منشأ البيانات؛ عند unavailable/invalid يظهر السبب صراحة ولا كلمة VERIFIED. لا تحول سلامة التوقيع إلى حكم قانوني أو صحة محتوى المعاملة.
- [ ] شغل الاختبارات الجديدة وtest_report_provenance.py وtest_forensic_report.py. شغل CLI في بيئة منفصلة بلا ai-engine/app أو DB، على ZIP صالح ومزور وبلا شبكة؛ ثم شغله --online على السلسلة المحلية الفعلية.
- [ ] سجل R09.md وأمثلة مخرجات خالية من البيانات الحساسة؛ راجع الفرق واحفظ commit محدوداً. RG2 لا يغلق قبل نجاح سلسلة upload→signed manifest→real anchor→snapshot→export→independent verifier.
