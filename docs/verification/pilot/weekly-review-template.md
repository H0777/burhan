# المراجعة الأسبوعية للتجربة — قالب weekly-NN (H11)

> يُحفظ كل أسبوع في `docs/verification/pilot/weekly-NN.md` (01، 02، ...)
> خلال 24 ساعة من إتمام الأسبوع. القياسات من Prometheus الحقيقي
> (`http://127.0.0.1:19090`) ولوحة `Burhan Staging — System Health (H07)`
> (`http://127.0.0.1:18300`)، ومعايير `docs/verification/pilot-exit-criteria.md`
> ملزمة. ملاحظة صادقة: لا Alertmanager — الجلب يدوي عبر API ويُثبت بالقيم
> أدناه.

```text
الأسبوع: NN   الفترة: 2026-__-__ → 2026-__-__ (UTC)
مُعدّ المراجعة: ______ (pilot_owner حقيقي)   التاريخ: ____

1) معايير الخروج (X1–X5) — قيم هذا الأسبوع
   X1 عبور مستأجرين: بطارية RLS (pytest ... = __ passed) + مسبار 0-صف: [PASS/FAIL]
   X2 فقد دليل:  stuck_outbox>300s = __  anchors_missing = __  عينة جلب __/__ VERIFIED
   X3 توقيع مزور: مسبار تزييف → [INVALID/أخرى]  tampered JWT → [401/أخرى]
   X4 تراكم outbox: max_over_time(burhan_outbox_oldest_pending_age_seconds[7d]) = __s
      إطلاقات (count_over_time ALERTS{BurhanOutboxOldestPendingStale}[7d]) = __ (كل إطلاق له صف حادثة)
      min_over_time(burhan_worker_heartbeat_age_seconds[7d]) = __s
   X5 استعادة: drill هذا الأسبوع؟ [نعم/لا]  النتيجة: ______ RPO=__ RTO=__

2) حوادث الأسبوع (من incidents.md): عدد __  SEV-1: __  مفتوحة: __
   خرائق معايير خروج: __ (إن >0 → القرار في incidents.md إلزامي)

3) صحة النظام (لقطة قيم يوم المراجعة)
   readiness: curl http://127.0.0.1:18080/api/v2/health/ready → __
   Prometheus targets: [up/down]   Grafana dashboard: [up/down]

4) الاستخدام الفعلي للمؤسسة (أرقام، لا PII)
   عمليات استيراد CSV: __   قضايا جديدة: __   أدلة: __   تحققات V3: __

5) ملاحظات المستخدمين/الجهة (حرفية، مؤرشفة)

6) بنود إصلاح جديدة (task/brief لكل بند) أو قرارات استمرار

7) قرار الأسبوع: [استمرار / إيقاف الكتابة + تقييم] — الاسم: ______
```
