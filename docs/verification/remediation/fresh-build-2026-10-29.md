# بناء نظيف موثّق — 29 أكتوبر 2026 (إغلاق إثبات DG0، مهمة H01)

الحالة: سجل تشغيل لإعادة البناء الكامل من التبعيات النظيفة على HEAD الحالي، لتحويل صفوف `findings.csv` وفق قاعدة الاعتماد. هذا المستند لا يعلن «جاهزية منتج»؛ يوثق ما الذي أثبته هذا البناء فعلياً وما لم يثبته.

## 1. الهوية والبيئة

| البند | القيمة |
|---|---|
| CI الأخضر المرجعي | run 40913812617 على commit `ff9f0c4` (فرع main، 6 بوابات خضراء على GitHub Actions، 2026-10-29) — https://github.com/H0777/burhan/actions/runs/40913812617 |
| HEAD المحلي عند التشغيل | `e6aaa74` — يختلف عن `ff9f0c4` بوثيقة الخطة فقط (`docs/superpowers/plans/2026-10-29-development-program.md`) |
| `build_id` المعتمد لصفوف VERIFIED_FIXED | `ff9f0c4` (البناء الأخضر الموقّع بالـCI؛ القبول يسمح به صراحة) |
| الفرع | `main` (كان يُدعى `codex/verified-remediation` تاريخياً؛ نفس خط الالتزامات) |
| البيئة | Windows 11 (cmd)، Node `v24.19.0`، npm `11.17.0`، Python `3.14.7` عبر `scripts/run-python.js`، Hardhat 2.x |
| ملاحظة بيئية | CI يشغّل Node 20 (عقود/تكامل) وNode 24 (واجهة)؛ التشغيل المحلي كله Node 24. لا توجد فروقات نتائج منسوبة لذلك في هذا التشغيل. |

## 2. mapping أوامر الخطة إلى أوامر فعلية

- `contracts:size` غير موجودة كسكربت npm في `package.json`؛ نفّذت مباشرة: `node scripts/check-contract-size.js` (بوابة R04/F08 نفسها). إضافة alias npm خارج نطاق ملفات هذه المهمة.
- `remediation:check` غير موجودة كسكربت npm؛ النص المُنشأ هذه المهمة `scripts/check-remediation-evidence.py` يُشغّل عبر: `node scripts/run-python.js scripts/check-remediation-evidence.py`. (كان مطلوباً في R20 ولم يُكتب أبداً — أُنشئ الآن بدل ادعاء تشغيله.)
- `npm run clean` (hardhat clean) أُضيف قبل `compile` لأن أول `npm run compile` أعاد «Nothing to compile» من كاش سابق — أُعيد الترجمة فعلياً من الصفر (11 ملف Solidity).

## 3. السلسلة الكاملة — كل أمر وexit code

| # | الأمر | النتيجة | exit code |
|---|---|---|---|
| 1 | `npm ci` (الجذر) | 629 حزمة، 43 ثانية | 0 |
| 2 | `npm --prefix frontend ci` | 375 حزمة، 19 ثانية | 0 |
| 3 | `npm run compile` (بعد `npm run clean` — إعادة ترجمة فعلية) | Compiled 11 Solidity files successfully | 0 |
| 4 | `node scripts/check-contract-size.js` (`contracts:size`) | 7 عقود ضمن ميزانية 24,000 بايت؛ الأكبر 19,723؛ AuditEngine 17,260 | 0 |
| 5 | `npm run contracts:check` | All contract ABIs match compiled artifacts (no drift) | 0 |
| 6 | `npm run test:contracts` | 206 passing (5s) — يشمل NoTestBackdoor وTimelockAndActionBinding وDeploymentInvariants | 0 |
| 7 | `npm run api:export` | Exported canonical OpenAPI V2 schema؛ لا انحراف في الملف المتعقب | 0 |
| 8 | `npm run api:check` | OpenAPI V2 schema is up to date (no drift) | 0 |
| 9 | `npm run verify:api` | node --test: 7 passed؛ OpenAPI: no drift؛ pytest: 221 passed, 81 skipped, 11 warnings (58.67s) | 0 |
| 10 | `npm run verify:frontend` | eslint: 0 errors / 242 warnings؛ vitest: 8 ملفات، 65 tests passed؛ build: √ built in 6.93s | 0 |
| 11 | `npm run verify:integration` | نشر كامل + bootstrap + محرك FastAPI؛ Playwright: 8 passed (2.7s) — «PASSED (0)» | 0 |
| 12 | `node scripts/run-python.js scripts/check-remediation-evidence.py` (`remediation:check`) | PASS — السجل متسق داخلياً (قيم وقت التشغيل الأولي: 14 صف FIXED_PENDING_VALIDATION) | 0 |

على إثر الخطوة 11 أعاد العدّاء كتابة `deployments/deployment-manifest.json` و`frontend/public/runtime-config.json` بقيم النشر المحلي المؤقتة (طوابع زمن/معرّفات سلسلة محلية)؛ أُعيدت الحالة الملتزمة بأمر `git checkout --` ولم يُstage أي منها. `git status` نظيف بعد السلسلة.

## 4. أي اختبار أحمر/أخضر في السجل شُغّل فعلاً في هذا البناء؟

قاعدة H01: `VERIFIED_FIXED` فقط لما غطّاه هذا البناء النظيف فعلياً. تحقق صريح للاختبارات المسمّاة في `findings.csv`:

| صف | الاختبار المسمّى في السجل | نتيجته في هذا البناء |
|---|---|---|
| F01 | `test/security/NoTestBackdoor.test.js:outsider_cannot_call_generation_setter` و`:production_abi_has_no_test_mutator` | ✅ شُغّلا ونجحا (ضمن 206) |
| F02 | `test/security/TimelockAndActionBinding.test.js:admin_cannot_bypass_after_bootstrap` | ✅ شُغّل ونجح |
| F03 | `test/security/TimelockAndActionBinding.test.js:timelock_boundaries` | ✅ شُغّل ونجح |
| F04 | `ai-engine/tests/integration/test_evidence_verification_v3.py:test_full_flow_verified` | ⏭️ SKIPPED — مجموعة R07 تشترط PostgreSQL مؤقتاً (DATABASE_URL/MIGRATION_DATABASE_URL)؛ لم يُثبَت في هذا البناء |
| F05 | الأحمر `test_export_signature.py:test_tampered_signature_bytes_invalid`؛ الأخضر `test_offline_mode_valid` | ✅ الأحمر شُغّل ونجح؛ الأخضر أُعيدت تسميته في الشيفرة إلى `test_offline_mode_valid_without_chain_claims` وشُغّل ونجح — حُدّث اسمه في السجل. المجموعة الكاملة (8 اختبارات توقيع/ثقة) غير مشروطة بـPostgreSQL وشُغّلت كلها |
| F06 | `test_anchor_crash_recovery.py:test_crash_after_claim_recovers` | ⏭️ المجموعة كلها (9 اختبارات) SKIPPED — تشترط PostgreSQL؛ لم يُثبَت في هذا البناء |
| F07 | `test_case_http.py:test_authenticated_paths_run_in_tenant_transaction` | ⏭️ SKIPPED — مجموعة R12 تشترط PostgreSQL؛ لم يُثبَت في هذا البناء |
| F08 | `test/security/DeploymentInvariants.test.js:size_gate_rejects_…` و`:fresh_standard_deployment` + بوابة الحجم (خطوة 4) | ✅ شُغّلت ونجحت؛ القياس الفعلي: AuditEngine 17,260 بايت ≤ 24,000 |
| F09 | اختبارات vitest لـruntime/AuthProvider (R13) | ✅ نجحت (65/65) لكن R13.md §6 يسجّل بقايا صريحة (issuer خارجي، E2E عبر nginx، V3) → جزئي |
| F10 | `test_identity_persistence.py:test_wallet_challenge_flow` | ⏭️ SKIPPED — مجموعة R10 تشترط PostgreSQL (وRLS كذلك)؛ لم يُثبَت في هذا البناء |
| F11 | `test_health_readiness.py:test_health_ready_evm_rpc_down_degrades_gracefully` | ✅ شُغّل ونجح، لكن جانب «manifest/RPC في الحاويات» من F11 لا يغطيه أي بند في هذه السلسلة → جزئي |
| F12 | `test_backup_recovery.py:test_snapshot_verification_and_tamper_detection` + اختبارات report-provenance | ✅ شُغّلت ونجحت (5/5 backup؛ provenance ضمن الـ221) — أسطح F12 الثلاثة مغطاة |
| F13 | اختبارات البحث/بوابة التقييم | ➖ خارج هذه السلسلة (لا يُشغّلها بند منها)؛ حالة R20 الأخيرة INSUFFICIENT_DATA (exit 2) صادقة ولم تتغير |
| F14 | E2E trust-flow (8/8 ✅) | ✅ الشهود نجحوا لكن أهداف الحمل (100 مستخدم/100 ألف سجل/30 دقيقة) لا يُجريها أي بند في السلسلة → لم تُثبَت |

تفصيل الـ81 skip في pytest: 80 اختبار PostgreSQL-gated (R07 chain-snapshot/verification-v3، R08 anchor/outbox/sender-nonce، R10 identity/membership، R11 RLS، R12 case-http/concurrency) + 1 اختبار symlink (امتياز Windows). لا يوجد أي skip آخر.

## 5. ما أثبته هذا البناء وما لم يثبته

**أُرقي إلى `VERIFIED_FIXED` (build_id=`ff9f0c4`)**: F01، F02، F03، F05، F08، F12 — كل صف منها سبقته مجموعة كاملة شُغّلت ونجحت في هذا البناء (الجدول أعلاه)، وأدلتها التاريخية `R01/R03/R04/R09/R16.md` بقيت كما هي. تفصيل القاعدة والحواف في `baseline-2026-10-23.md` §4 (ملاحظة 2026-10-29).

**يبقى `FIXED_PENDING_VALIDATION`**: F04، F06، F07، F09، F10، F11، F13، F14 — السبب لكل صف في ملاحظة baseline §4 المشار إليها أعلاه. لم يُجبَر أي صف على الترقية.

## 6. حدود هذا السجل

- هذا تشغيل محلي واحد على Windows؛ التوقيع الأخضر عبر الـCI (6 بوابات) على `ff9f0c4` هو المرجع المشترك. لا يُستخلص من هذا المستند أي ادعاء جاهزية إنتاج أو إقلاع مؤسسي (DG0 فقط — إغلاق إثبات).
- بوابات CI غير مغطاة محلياً: فحص الأسرار (`secret-and-quality-audit`) يعمل في الـCI فقط؛ smoke النشر المحلي في CI يقابله خطوتا 11 أعلاه.
