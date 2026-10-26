# إصلاح الهوية والبيانات والتشغيل — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** تشغيل مؤسسي فعلي بصلاحيات وعزل وواجهات وعمال واستعادة، دون الاعتماد على إعدادات demo أو اختبارات SQLite لإثبات الإنتاج.

**Architecture:** هوية موثقة مرتبطة بعضوية ومحفظة ثابتة، وPostgreSQL بدور محدود وtenant context لكل معاملة. الواجهة والخادم والعمال يستهلكون سجل نشر واحداً، وتُقاس الجاهزية من هذه التبعيات.

**Tech Stack:** FastAPI/SQLAlchemy/PostgreSQL 16، React 18/Vite 5، Docker Compose، OIDC، pytest/Vitest/Playwright.

**Spec:** [§3 و8–9 من التصميم](../specs/2026-10-23-verified-remediation-design.md).

## Global Constraints

- APP_MODE=demo أو institutional صراحة؛ institutional لا يسمح بهوية تجريبية أو مفاتيح/RPC احتياطية.
- PostgreSQL app role غير مالك وNOSUPERUSER NOBYPASSRLS وبلا DDL؛ migrations بحساب منفصل.
- واجهة التحقق /api/v3/evidence/verify، وباقي V2 محفوظ؛ api_origin="" أو origin مطلق بلا /api.
- لا أسرار في runtime-config أو manifest أو Git أو logs؛ خدمات العمال مستقلة عن HTTP.
- حدود الاستعادة المقترحة RPO<=15 دقيقة وRTO<=120 دقيقة تُقاس، ولا تُعلن محققة مسبقاً.
- ترتيب تعديل الملفات المشتركة عند مالكها الوحيد في [الخارطة](2026-10-23-remediation-roadmap.md).

## Review Focus

1. connection pool يعيد اتصال مؤسسة A إلى B — R11 يختبر عدم تسرب السياق.
2. عضوية معطلة وJWT ما زال صالحاً — R10 يرفض الهوية فوراً.
3. طلبان يعدلان نسخة القضية نفسها — R12 يقبل انتقالاً واحداً و409 للآخر.
4. runtime-config غير موجود أو chain/account يتغيران — R13 يمنع الكتابة ويطلب إعادة الربط.
5. نسخ أو استعادة أثناء outbox SUBMITTED — R16 يصالح السلسلة قبل استئناف العمال.

## R10 — هوية مؤسسية مستمرة وربط محفظة صحيح

**الاعتماد:** R02، R11؛ ترتيب التنفيذ ليس ترتيب أرقام الوثيقة. **المالك:** الهوية.

**الملفات:** تعديل ai-engine/app/security/oidc.py وwallet_binding.py وtenant_context.py وroutes/v2/identity.py وschemas/identity.py وrepositories/institution_repository.py. إنشاء repositories/wallet_binding_repository.py وtests/integration/test_identity_persistence.py وtest_membership_revocation.py. تحديث tests/test_identity.py. إضافة migration wallet_challenges عبر مالك DB؛ تعديل config.py/main.py بواسطة مالك التشغيل.

**الواجهات:**

    resolve_identity(session:Session,claims:dict) -> Identity
    WalletBindingRepository.consume_challenge(session,challenge_id:str,
                                              institution_id:str,sub:str,now:datetime) -> ChallengeRecord
    WalletBindingService.get_active_binding(institution_id:str,sub:str) -> BindingRecord | None

الحفاظ على response identity الحالي مع participant_id/generation ومحفظة موثقة، دون إرجاع token أو challenge secret. تحدد الأدوار من membership، والربط من DB وRoleManager. OIDC issuer/audience/algorithms مسموحة صراحة، claims exp/iat/nbf/sub إلزامية وclock skew=60s. صلاحية challenge=300s واستهلاكه compare-and-swap ذري.

- [ ] أضف institutional_no_bearer_401 وoidc_disabled_startup_fails وmissing_exp_or_audience_rejected وjwt_role_cannot_create_membership وinactive_membership_forbidden. الهوية التجريبية لا تظهر عند فشل مزود OIDC.
- [ ] أضف challenge_survives_process_restart، consume_once_two_sessions، expired_at_300s، wrong_chain_domain_sub_rejected، rotated_wallet_generation_rejected. اختبر challenge لمحفظة لا يثبت أنها participant قبل القراءة من السلسلة.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_identity_persistence.py ai-engine/tests/integration/test_membership_revocation.py؛ سجل الفشل الحالي.
- [ ] استبدل InMemoryWalletBindingRepo في institutional بمستودع DB، واحفظ challenge/المستخدم/المؤسسة/domain/chain/nonce/expires/consumed_at؛ unique challenge nonce وقيد محفظة فعالة واحدة للعضوية.
- [ ] تحقق من العضوية على كل طلب، ومن الجيل/الدور على السلسلة قبل الكتابات الحساسة. عند تعطل قراءة الترخيص أعد 503، لا تفوض بالادعاء الموجود في المتصفح. demo له dependency صريحة ومعزولة.
- [ ] شغل الاختبارات الجديدة وtest_identity.py؛ ثم استخدم خادم OIDC اختباري بتوقيع JWT فعلي وقاعدة PostgreSQL وعقود R02. تعطيل مستخدم بعد إصدار token يمنعه من طلب لاحق.
- [ ] سجل R10.md وراجع الفرق؛ commit محصور. سلّم Identity إلى R07/R12 والواجهة، مع ثبات أسماء حقول JSON.

## R11 — migrations وعزل PostgreSQL حقيقي

**الاعتماد:** R00. **المالك:** مهندس DB.

**الملفات:** تعديل ai-engine/app/db/session.py وmodels.py وsecurity/tenant_context.py وtests/integration/test_tenant_storage.py. إنشاء ai-engine/alembic.ini وapp/db/migrations/env.py وversions/r11_baseline.py وops/postgres/init-roles.sql وtests/integration/test_postgres_rls.py. أي إضافة Alembic/psycopg لازمة تثبت في requirements عبر قائد التكامل. تعديل docker-compose لاحقاً بمالك R14.

**الواجهة:** tenant_transaction(session:Session,institution_id:str)->ContextManager[Session] يحفظ توقيعه الحالي؛ يستخدم set_config transaction-local. مسار بدء institutional يتحقق من schema revision ولا يستدعي create_all أو seed. ترحيل قاعدة حالية يتضمن مقارنة schema بالـbaseline قبل stamp؛ لا stamp تلقائي لقاعدة مجهولة.

- [ ] أضف app_role_flags_limited، tenant_a_cannot_select_update_delete_b، insert_wrong_tenant_rejected، no_context_reads_nothing وconnection_reused_does_not_leak. استخدم اتصالين فعليين بدور التطبيق لا superuser في assertions.
- [ ] أضف migrations_from_empty_and_existing_fixture وrole_cannot_ddl وrollback_clears_context. افحص FORCE ROW LEVEL SECURITY وFK/unique المؤسسية على جميع جداول البيانات المؤسسية، بما فيها outbox والتقارير والعضوية والربط.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_postgres_rls.py مع DATABASE_URL لدور التطبيق وMIGRATION_DATABASE_URL للدور المالك على DB اختبار فقط؛ اختبر أن متغير المالك غير متاح لعملية API.
- [ ] أنشئ baseline/migrations وapp role دون ownership أو BYPASSRLS، وحدد grant الحد الأدنى للجداول/sequences. استخدم SELECT set_config('app.current_institution_id', :id, true) داخل المعاملة، ولا SET LOCAL بbind غير صالح.
- [ ] ألزم routes/repositories/العمال بسياق مؤسسي قبل استعلام بيانات؛ لا تتجاوز RLS بإتاحة admin engine للعملاء. أي جدول global مثل institutions له سياسة وصول صريحة، لا اعتباره آمناً لأنه بلا institution_id.
- [ ] شغل migrations upgrade head ثم الاختبارات الجديدة وtest_tenant_storage.py؛ اختبارات SQLite تبقى اختبارات منطق فقط وتُسمى كذلك.
- [ ] سجل R11.md مع نتائج pg_roles وowners والسياسات دون credentials؛ راجع الفرق وcommit محصوراً. لكل revision لاحقة اسم فريد وdown_revision إلى HEAD الحالي وقت دمج مالك DB؛ لا تربط down_revision بأرقام مهام الخطة أو تترك عدة heads.

## R12 — مسارات القضايا والتزامن وidempotency

**الاعتماد:** R10، R11. **المالك:** API/القضايا.

**الملفات:** تعديل ai-engine/app/routes/v2/cases.py وservices/case_service.py وrepositories/case_repository.py وschemas/cases.py. إنشاء tests/integration/test_case_http.py وtest_case_concurrency_postgres.py، وتحديث test_case_workflow.py. تعديلات IdempotencyKey بالـmigration من مالك DB إذا احتاج المخطط الحالي الحقول المحددة.

**الواجهات:** إصلاح create/list/get/transition باستخدام with tenant_transaction(db,identity.institution_id). إنتاج update_case_status(session,institution_id:str,case_id:str,expected_version:int,new_status:str,updates:dict)->Case أو CaseVersionConflict. body idempotency digest يشمل كل الحقول الدلالية؛ نطاق المفتاح institution+sub+method+path+key؛ TTL=24 ساعة، ولا يعاد تشغيل نفس المفتاح قبل انقضائه.

- [ ] أضف http_create_list_get_transition_no_500 باستخدام TestClient عبر routers الحقيقية دون override لخدمة القضايا أو tenant_transaction؛ هوية اختبار موثقة وDB فعلي. اختبر 401/403/404 وinvalid_transition_409.
- [ ] أضف concurrent_expected_version_one_winner بجلستين وbarrier قبل UPDATE؛ النتيجة نجاح واحد و409 واحد وزيادة version بمقدار1 وCaseEvent واحد. exception_after_event_rolls_back_all يعيد الحالة/الحدث/idempotency معاً.
- [ ] أضف same_key_different_description_or_severity_409 وtransition_new_assignee_changes_digest_409 وsame_request_returns_same_response. أضف pagination_two_pages_no_duplicates مع ترتيب ثابت created_at,id وcursor مربوط بالمؤسسة والفلاتر.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_case_http.py ai-engine/tests/integration/test_case_concurrency_postgres.py؛ أظهر TypeError الحالي على HTTP واختبار التزامن الفاشل منفصلين.
- [ ] صحح الاستدعاءات الأربعة، ونفذ SQL UPDATE WHERE institution_id/case_id/version مع rowcount/RETURNING. الحدث والنتيجة في المعاملة نفسها، وunique constraint لحجز idempotency؛ لا Python version check وحده.
- [ ] أكمل cursor التالي إذا وُجد limit+1، وارفض cursor مؤسسة أخرى؛ لا تعِد next_cursor=None مع بقاء نتائج.
- [ ] شغل الاختبارات الجديدة وtest_case_workflow.py ثم npm run api:export وnpm run api:check؛ سجل R12.md وراجع الفرق وcommit محصوراً.

## R13 — إعداد الواجهة والعميل والهوية بعد التحميل

**الاعتماد:** R04، R07، R12. **المالك:** الواجهة؛ لا تصميم بصري جديد.

**الملفات:** تعديل frontend/src/config/runtime.js وmain.jsx وapi/client.js وauth/AuthProvider.jsx وutils/aiClient.js وhooks/useAuditEngine.js، وpublic/runtime-config*.json. إنشاء src/auth/oidcClient.js وsrc/auth/LoginScreen.jsx وsrc/auth/oidcClient.test.js وsrc/config/runtime.test.js وsrc/api/client.test.js؛ تحديث AuthProvider.test.jsx وuseAuditEngine.test.jsx وcomponents/CaseWorkspace.test.jsx. تثبيت oidc-client-ts بإصدار محدد متوافق مع build وتحديث frontend/package.json وpackage-lock.json بواسطة قائد التكامل؛ لا ترقية بقية الأطر. توليد api/generated/schema.d.ts من عقد V2+V3.

**الواجهات:**

    loadRuntimeConfig(): Promise<RuntimeConfig>
    getRuntimeConfig(): RuntimeConfig // throws before successful load
    isInstitutionalMode(): boolean // reads resolved config, no build-time cached boolean
    createApiClient(config:RuntimeConfig): ApiClient
    ApiClient.request(path:string,options:RequestInit): Promise<unknown>
    beginLogin(): Promise<void>
    completeLogin(callbackUrl:string): Promise<Identity>
    endLogin(): Promise<void>

RuntimeConfig: app_mode، api_origin، chain_id، rpc_url، deployment_id، contracts، oidc={authority,client_id,redirect_uri,scope}. حقول OIDC مطلوبة في institutional فقط، وredirect_uri=origin+/auth/callback مسجل لدى issuer. يرفض api_origin ذا /api؛ config schema صارم. paths تبدأ /api/v2 أو /api/v3 مرة واحدة، و/api/v3/evidence/verify يستخدم IDs فقط. fetch للهوية من العميل نفسه، لا concatenation للـbase مع /api/v2 في مسارات متفرقة.

- [ ] أضف runtime_institutional_controls_mode_after_fetch وmissing_invalid_config_blocks_rendered_writes وsame_origin_has_one_api_prefix وexternal_origin_preserves_path. تأكد من غياب 127.0.0.1 الصريح من إعداد عميل institutional.
- [ ] أضف wrong_chain_even_31337_rejected وaccount_or_chain_change_clears_identity وstale_signature_result_ignored وno_getSigner_zero_fallback. لا يظل submit مفعلاً أثناء تحميل config/identity/wallet.
- [ ] أضف login_redirect_callback_state_nonce_checked وcallback_replay_rejected وexpired_token_clears_identity وlogout_clears_session. beginLogin يغلف UserManager.signinRedirect وcompleteLogin يغلف signinCallback ثم identity/me؛ لا client_secret أو password grant أو token يدوي في institutional. مرجع الواجهات: [توثيق UserManager الرسمي](https://authts.github.io/oidc-client-ts/classes/UserManager.html)، و[مصدر PKCE الرسمي](https://github.com/authts/oidc-client-ts/blob/main/src/OidcClient.ts).
- [ ] شغل npm --prefix frontend test -- --run src/config/runtime.test.js src/api/client.test.js؛ يجب أن يثبت الاختبار خطأ mode والـURL الحاليين.
- [ ] نفذ مصدر إعداد واحد بعد التحميل، وعرض حالة config_error قابلة للفهم وإعادة المحاولة. أزل finally-render الذي يخفي فشل الإعداد، ومرر config إلى العميل/providers/hooks دون race مع singleton قديم. أضف شاشة دخول/callback وإدارة token expiry؛ تخزن الحالة مؤقتاً في sessionStorage أو memory وتزال عند logout، دون localStorage أو logs.
- [ ] حدّث UI لتمييز pending/submitted/anchored وverified/invalid/unavailable وحالة demo/legacy؛ لا تعرض blockchain success عند HTTP upload فقط. تعامل مع 410 القديم بانتقال واضح إلى V3 دون قبول entries قديمة تلقائياً.
- [ ] شغل npm run verify:frontend وnpm run api:check؛ lint بلا errors وتحذيرات مرتبطة جديدة=0، ثم اختبر build المقدم عبر nginx وsame-origin الفعلي في R20.
- [ ] سجل R13.md وراجع الفرق وcommit محصوراً. لا تغيّر Vite/React أو شكل الصفحات لمعالجة URLs.

## R14 — حاويات قابلة للتشغيل وعمال وسجل نشر واحد

**الاعتماد:** R04، R08، R10، R11، R13. **المالك:** التشغيل؛ يمتلك config/main/Compose/scripts المشتركة أثناء المهمة.

**الملفات:** تعديل docker-compose.yml وhardhat.config.js وscripts/deploy.js وai-engine/Dockerfile وfrontend/Dockerfile وfrontend/nginx.conf وai-engine/app/config.py وmain.py وscripts/run-integration.js وrun-integration.ps1. إنشاء docker-compose.institutional-test.yml وops/render-runtime-config.js وtests/integration/compose-smoke.mjs وtests/fixtures/oidc/issuer.py.

**العقد:** dev يحدد APP_MODE=demo، والمنافذ 127.0.0.1 فقط. ملف institutional-test يحتاج أسرار اختبار مولدة مؤقتاً وOIDC issuer حقيقياً من fixture، ويستخدم DB app role وworkers. ليس قالب نشر إنتاجي لعقدة Hardhat غير مقفلة.

مصدر manifest volume مخصص: deployer write، وAPI/anchor/indexer read-only. renderer يتحقق schema وcode hash/deployment status ويولد public runtime config خالياً من أسرار؛ يُقدم الملف نفسه للواجهة دون embedding قيم VITE وقت build. BLOCKCHAIN_RPC_URL في hardhat.config يأخذ URL الخدمة داخل Docker، والمتصفح يستخدم URL يمكن للمستخدم الوصول إليه؛ لا يسرّب اسم hardhat-node إلى المتصفح.

- [ ] أضف compose_config_has_no_superuser_api ولا binds للجذر rw في institutional-test ولا منافذ عامة لـDB/RPC؛ manifest_ready_before_api؛ workers_have_correct_entrypoint؛ frontend_reads_current_deployment.
- [ ] أضف clean_start_deploys_without_loopback_error وmissing_manifest_api_unready وsame_origin_identity_200 وworker_anchors_uploaded_file. لا تستخدم sleep ثابتاً لتعويض dependencies.
- [ ] شغل node --test tests/integration/compose-smoke.mjs لتثبيت العيوب الحالية؛ اختبارات التشغيل تنشئ مشروع Docker ذا اسم ومسارات وvolumes خاصة بالاختبار فقط.
- [ ] أصلح RPC env، وbuild contexts بحيث تصل shared schemas/crypto/ABIs إلى صور الخدمة دون نسخ أسرار أو node_modules. لا npm install عند بدء حاوية مؤسسية؛ تبنى الصور من lockfiles.
- [ ] أضف خدمات migrate ثم deploy/verify ثم runtime renderer ثم API والعمال ثم الواجهة بشروط health/completion. يبدأ العمال دون انتظار /ready للـAPI الذي يفحص heartbeat، لمنع dependency cycle. fixture OIDC تدعم discovery/JWKS/authorization/token وPKCE/callback للمتصفح الاختباري، دون استعمالها في الإنتاج. failures تمنع الخدمة التابعة، ولا تنتج manifest تجريبياً بديلاً. volumes دائمة للأدلة/DB منفصلة عن artifact volume.
- [ ] شغل docker compose -f docker-compose.yml -f docker-compose.institutional-test.yml config ثم دورة build/up لمشروع الاختبار؛ اختبر الهوية/QC/القضية/الرفع والتثبيت من origin الواجهة.
- [ ] سجل R14.md وproject name/صور ومنافذ وpaths؛ أوقف واحذف موارد الاختبار التي أنشأتها هذه المهمة فقط بعد فحص أسمائها، دون down -v على مشروع المستخدم. راجع الفرق وcommit محصوراً.

## R15 — جاهزية تقيس الواقع

**الاعتماد:** R14. **المالك:** التشغيل/API.

**الملفات:** تعديل ai-engine/app/routes/v2/health.py وservices/policy_service.py وconfig.py وmain.py. إنشاء app/services/readiness_service.py وtests/integration/test_readiness_dependencies.py. تحديث tests/test_policy_service.py وdocs/runbooks/local-start.md. حالة ML من نتيجة R18 عند دمجها؛ الافتراضي المؤسسي rule_based.

**الواجهة:** ReadinessService.check(now:datetime)->ReadinessResult {status,checks,checked_at,build_id}. المسارات الحالية GET /api/v2/health/live و/api/v2/health/ready تحفظ كما تسجلها main.py:70؛ /live و/ready هنا اختصار لمعناهما، ولا تنشأ مسارات متنافسة. liveness=200 للعملية الحية، readiness=200 فقط عند الجاهزية و503 خلاف ذلك. statuses لا تتضمن tokens أو SQL/DSN كامل. startup invariant mismatch مثل OIDC off يمنع البدء أصلاً.

- [ ] اكتب DB_down، wrong_migration، app_role_superuser، rpc_down، codehash_mismatch، store_canary_failure، missing_signing_key، worker_heartbeat_121s، oldest_due_outbox_301s؛ جميعها /ready=503 وcheck محدد failed.
- [ ] أضف no_default_policy_claimed_on_chain؛ عند RPC مفقود لا يعاد default ETH باعتباره سياسة سلسلة. أضف ml_enabled_missing_artifact_503 وml_disabled_explicitly_ready وbad_model_hash_503 وactual_inference_failure_503.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_readiness_dependencies.py؛ سجل الفرق عن ready الحالي.
- [ ] نفذ فحوص actual session/registry/code/RPC والسياسة الفعلية والcanary المعزول heartbeat والمفاتيح والنموذج عند تفعيله؛ canary خارج namespace الأدلة ولا ينشئ EvidenceObject.
- [ ] نفذ timeouts محدودة لكل فحص: ثانيتان وdeadline كلي خمس ثوانٍ، cache لمدة خمس ثوانٍ للنتائج غير الحساسة؛ لا تجعل /ready يشغل تدريب ML أو ينتظر تأكيد معاملة.
- [ ] شغل الاختبار الجديد وtest_policy_service.py، ثم افصل كل تبعية في الحاويات وأثبت التحول إلى503 والعودة إلى200 بعد الإصلاح. سجل R15.md وcommit محصوراً.

## R16 — نسخ احتياطي حقيقي واستعادة آمنة

**الاعتماد:** R05، R06، R08، R11. **المالك:** التشغيل/DB.

**الملفات:** تعديل ai-engine/app/services/backup_service.py وops/backup.py وbackup.ps1 وdocs/runbooks/recovery.md وdocs/verification/recovery-drill.md. إنشاء ops/restore.py وops/backup-policy.example.json وai-engine/tests/integration/test_postgres_backup_restore.py وtest_backup_archive_validation.py. تحديث test_recovery_and_backup.py.

**الواجهات:** create_backup(...)->BackupDescriptor مع db_format=pg_custom، schema_revision، snapshot_id، manifest_digest، key_ids، consistency_boundary. restore_backup(bundle:Path,target_db_url:str,target_evidence_dir:Path,registry:TrustRegistry)->RestoreResult؛ يرفض هدفاً موجوداً أو مطابقاً للمصدر. مفتاح فك النسخ من KeyProvider خارج الحزمة.

النسخة ليست pg_dump ثم نسخ عشوائي لكل القرص: استعمل pg_export_snapshot في معاملة طويلة بحد زمني، وشغل pg_dump --format=custom --snapshot مع قراءات قائمة evidence/outbox/checkpoints من نفس اللقطة. retention/GC لا يحذف نسخاً مرجعية أثناء النسخ. يضم manifest الملفات المشار إليها فقط وبصمات ciphertext وبيانات encryption references؛ لا يضم مفاتيح خاصة.

- [ ] اكتب postgres_restore_preserves_types_constraints_rls وsnapshot_consistent_under_writes وno_sqlite_fallback_for_postgres وciphertext_corruption_detected وforged_backup_signature_rejected.
- [ ] أضف zip_traversal_duplicate_limit_rejected قبل extraction، existing_target_refused، missing_old_encryption_key_unavailable، restored_pending_tx_reconciles_once. لا تُعد raw SQL/untrusted archive تعليمات تنفيذ؛ pg_restore يستعمل ملفات ولدت من نسخة موثقة فقط وحساب استعادة معزول.
- [ ] شغل node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_postgres_backup_restore.py ai-engine/tests/integration/test_backup_archive_validation.py؛ تثبت الاختبارات فشل PostgreSQL fidelity الحالي دون لمس قاعدة المستخدم.
- [ ] نفذ snapshot وpg_dump/restore بدلاً من ترحيل PostgreSQL إلى SQLite؛ بحساب صيانة audit_backup له SELECT وBYPASSRLS دون superuser أو DDL ومفصول تماماً عن API/العمال. أنشئ archive داخلياً، شفّره AES-GCM بمفتاح ملفوف، ثم وقع manifest خارجياً بـAML_BACKUP_V1 يحمي ciphertext SHA-256/size وwrapped_key/nonce/tag وinner_manifest_digest. أبق snapshot/advisory retention lock حتى اكتمال الفهرس والdump، وافشل عند تجاوز حد التنفيذ بدلاً من dump غير متسق.
- [ ] الاستعادة تسلسل: تحقق outer signature وciphertext digest ثم فك GCM في staging محمي ثم تحقق inner inventory ثم DB جديدة ثم الملفات ثم migrations المتوافقة وفحص RLS ثم codehash/canonical checkpoint/outbox reconciliation؛ العمال موقوفون حتى نهاية المصالحة. حساب الاستعادة لا يملك الاتصال بقاعدة الإنتاج.
- [ ] نفذ drill بحجم مرجعي 100,000 معاملة وأدلة ممثلة، وسجل آخر commit بيانات مستعاد ومدد الاكتشاف/التهيئة/الاستعادة/المصالحة. قارن RPO<=15m وRTO<=120m وجرّب corruption ومفتاحاً مفقوداً.
- [ ] شغل الاختبارات الجديدة وtest_recovery_and_backup.py؛ حدّث الوثائق بالنتائج الفعلية وحدودها وR16.md. لا تصف hash ذاتياً بأنه توقيع، ولا تعلن أهداف RPO/RTO ناجحة قبل القياس؛ راجع الفرق وcommit محصوراً.

## التسليم

بعد R10–R16 يسلم الفريق credentials names دون قيمها، وschema revisions، وعناوين origin/RPC المختبرة، ونسخ صور الخدمات، ونتائج ready/restore. إعادة تشغيل خدمة أو تغيير account/chain جزء من قبول R20، وليس بنداً وثائقياً يكفي وضع علامة أمامه.
