# سجل حوادث التجربة — قالب (H11)

> صف واحد لكل حادثة في ملف `docs/verification/pilot/incidents.md`
> (يُنشأ عند بدء التجربة). التصنيف حسب `docs/runbooks/incident-response.md`
> (SEV-1..SEV-4) والاستجابة حسب runbook التنبيه المعني
> (`docs/runbooks/alert-*.md`). **كل إطلاق تنبيه Prometheus أثناء
> التجربة يجب أن يكون له صف هنا** — حتى الذي يُحلّ ذاتياً (X4 في
> `docs/verification/pilot-exit-criteria.md`).

| # | التاريخ/الوقت UTC | SEV | المصدر (تنبيه/اكتشاف) | الوصف (بلا PII/أسرار) | runbook المتبع | الإجراء الفوري | الأثر (دقائق/نطاق) | الجذر | القرار (استمرار/إيقاف + من قرر) | أُغلق UTC | دليل |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-__-__T__:__Z | | مثال: `BurhanOutboxOldestPendingStale` من `/api/v1/alerts` | | docs/runbooks/alert-outbox-stalled.md | | | | | | |
| 2 | | | | | | | | | | | |

قواعد:
- **خرق معيار خروج (X1–X5) = إيقاف الكتابة أولاً** ثم التقييم ثم القرار
  الموثق باسم pilot_owner (قاعدة H12 — لا تجاوز).
- لا أسماء مستخدمين/بيانات معاملات في الوصف — المعرفات المؤسسية فقط.
- عمود `دليل`: مسار ملف/لقطة قيم (log excerpt, PromQL snapshot, docker ps).
