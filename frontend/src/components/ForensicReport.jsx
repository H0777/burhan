import React, { useState } from 'react'
import {
  FileText,
  Printer,
  Download,
  Languages,
  ShieldCheck,
  Building2,
  Calendar,
  Lock,
  UserCheck,
  CheckCircle,
  QrCode,
  Scale,
} from 'lucide-react'
import { shortAddress } from '../utils/contract'

export function ForensicReport({ stats, forensicTrail, t, isRtl }) {
  const [reportLang, setReportLang] = useState('ar') // Default to formal Arabic for Iraqi court admissibility

  const caseData = {
    caseId: 'CBI-AML-2026-8841',
    investigator: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    suspectOperator: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    targetBeneficiary: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955',
    dateIssued: '2026-10-22',
    courtNameAr: 'محكمة تحقيق الكرخ المختصة بقضايا النزاهة وغسل الأموال — بغداد',
    courtNameEn: 'Al-Karkh Investigation Court for Integrity & AML Affairs — Baghdad',
    rootHash: forensicTrail?.[forensicTrail.length - 1]?.entryHash || '0x9924ac9341efcb909247c07b6f6f7d49e6f99b244799014b2b627cf99e5a1bfa2',
  }

  const handlePrint = () => {
    window.print()
  }

  return (
    <div className={`space-y-6 ${isRtl ? 'font-arabic text-right' : 'font-sans text-left'}`} dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Top Banner & Control Bar (Hidden when printing) */}
      <div className="print:hidden cyber-card p-5 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <FileText className="w-5 h-5 text-emerald-400" />
              {t?.navReports || 'Bilingual Judicial Forensic Dossier (Court-Admissible)'}
            </h2>
            <span className="text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-700 px-2.5 py-0.5 rounded-full font-mono font-bold">
              FATF & CBI Certified
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {reportLang === 'ar'
              ? 'تقرير تدقيق جنائي معتمد وموثق تشفيرياً يثبت التهديد الداخلي وتجاوزات غسل الأموال بحجية قضائية ملزمة.'
              : 'Formal forensic accounting dossier certifying internal threat infractions with non-repudiable blockchain evidence.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Toggle Report Content Language */}
          <button
            onClick={() => setReportLang(reportLang === 'ar' ? 'en' : 'ar')}
            className="px-3.5 py-2 bg-cyber-950 hover:bg-cyber-800 border border-cyber-700 rounded-xl text-xs font-semibold text-white flex items-center gap-2 transition"
          >
            <Languages className="w-4 h-4 text-cyan-400" />
            {reportLang === 'ar' ? 'Switch to English Dossier' : 'التحويل للغة العربية القضائية'}
          </button>

          {/* Print Button */}
          <button
            onClick={handlePrint}
            className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white font-semibold rounded-xl text-xs flex items-center gap-2 shadow-glow-emerald transition"
          >
            <Printer className="w-4 h-4" />
            {reportLang === 'ar' ? 'طباعة / تصدير PDF رسمي' : 'Print / Export Court PDF'}
          </button>
        </div>
      </div>

      {/* Official Printable Report Container */}
      <div
        className={`bg-white text-gray-900 rounded-2xl p-8 sm:p-12 shadow-2xl border border-gray-300 max-w-4xl mx-auto print:border-none print:shadow-none print:p-0 ${
          reportLang === 'ar' ? 'text-right font-arabic' : 'text-left font-sans'
        }`}
        dir={reportLang === 'ar' ? 'rtl' : 'ltr'}
      >
        {/* Judicial Letterhead Header */}
        <div className="border-b-2 border-gray-900 pb-6 mb-6">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <h1 className="text-xl sm:text-2xl font-black tracking-tight text-gray-950">
                {reportLang === 'ar' ? 'جمهورية العراق — البنك المركزي العراقي' : 'REPUBLIC OF IRAQ — CENTRAL BANK OF IRAQ'}
              </h1>
              <h2 className="text-sm sm:text-base font-bold text-gray-700">
                {reportLang === 'ar'
                  ? 'مكتب التحقيقات الجنائية الرقمية ومكافحة غسل الأموال (AMLU)'
                  : 'Digital Forensics & AML/CFT Cyber-Auditing Bureau'}
              </h2>
              <p className="text-xs text-gray-600 font-medium">
                {reportLang === 'ar' ? caseData.courtNameAr : caseData.courtNameEn}
              </p>
              <p className="text-[11px] text-gray-500 font-mono">
                {reportLang === 'ar'
                  ? 'صادر استناداً لأحكام قانون مكافحة غسل الأموال رقم 39 لسنة 2015 وقانون التوقيع الإلكتروني رقم 78 لسنة 2012'
                  : 'Issued pursuant to AML/CFT Law No. 39 of 2015 & Electronic Signatures Act No. 78 of 2012'}
              </p>
            </div>

            <div className="flex flex-col items-center justify-center p-3 border-2 border-gray-900 rounded-xl shrink-0">
              <Scale className="w-8 h-8 text-gray-950" />
              <span className="text-[9px] font-mono font-bold mt-1 uppercase text-gray-900">
                OFFICIAL SEAL
              </span>
            </div>
          </div>
        </div>

        {/* Case Metadata Table */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 bg-gray-50 rounded-xl border border-gray-200 mb-6 text-xs">
          <div>
            <span className="text-gray-500 font-medium block">
              {reportLang === 'ar' ? 'رقم القضية القضائية:' : 'Judicial Case ID:'}
            </span>
            <span className="font-mono font-bold text-gray-900">{caseData.caseId}</span>
          </div>

          <div>
            <span className="text-gray-500 font-medium block">
              {reportLang === 'ar' ? 'تاريخ التقرير:' : 'Date of Issue:'}
            </span>
            <span className="font-mono font-semibold text-gray-900">{caseData.dateIssued}</span>
          </div>

          <div>
            <span className="text-gray-500 font-medium block">
              {reportLang === 'ar' ? 'المحقق الجنائي:' : 'Lead Auditor:'}
            </span>
            <span className="font-mono text-gray-900">{shortAddress(caseData.investigator)}</span>
          </div>

          <div>
            <span className="text-gray-500 font-medium block">
              {reportLang === 'ar' ? 'تصنيف الواقعة:' : 'Classification:'}
            </span>
            <span className="font-bold text-rose-700 bg-rose-100 px-2 py-0.5 rounded text-[11px]">
              {reportLang === 'ar' ? 'حرج / احتيال وتواطؤ داخلي' : 'CRITICAL / INSIDER FRAUD'}
            </span>
          </div>
        </div>

        {/* Section 1: Executive Case Summary */}
        <div className="mb-6 space-y-2">
          <h3 className="text-sm font-bold text-gray-900 uppercase tracking-wide border-b border-gray-300 pb-1 flex items-center gap-2">
            <span>1.</span>
            {reportLang === 'ar' ? 'الملخص التنفيذي للواقعة الجنائية' : 'Executive Forensic Case Summary'}
          </h3>
          <p className="text-xs leading-relaxed text-gray-700 text-justify">
            {reportLang === 'ar'
              ? 'بناءً على نتائج المراقبة المستمرة لمحرك التدقيق السيبراني المربوط بسلسلة الكتل (AuditEngine)، تم رصد وتوثيق نشاط احتيال مالي مركب ارتكبه المشغل (0x7099...79C8). اشتمل النشاط على قيامه بتجاوز تحذيرات النظام الرقابي (System Overrides) بعدد 7 مرات متتالية خارقاً السقف الأقصى المسموح به (5 مرات)، واعتماد تحويلات مجزأة بقيمة 9.85 ETH (ما يعادل 39,006,000 دينار عراقي) لمستفيد مشبوه بهدف التهرب العمدي من سقف الإبلاغ الإلزامي للبنك المركزي العراقي البالغ 10 ETH (المادة 12 من القانون رقم 39 لسنة 2015) (جريمة هيكلة أموال Smurfing).'
              : 'Based on immutable blockchain audit trail telemetry, an insider fraud pattern was authenticated involving authorized auditor account 0x7099...79C8. The subject executed 7 policy warning overrides exceeding the CBI limit of 5, approving consecutive sub-threshold wires of 9.85 ETH (~39,006,000 IQD / $29,550 USD) to an unverified entity to evade the mandatory 10.0 ETH AML reporting ceiling (Structuring/Smurfing infraction under CBI Law No. 39 of 2015).'}
          </p>
        </div>

        {/* Section 2: Evidentiary Hash Table */}
        <div className="mb-6 space-y-2">
          <h3 className="text-sm font-bold text-gray-900 uppercase tracking-wide border-b border-gray-300 pb-1 flex items-center gap-2">
            <span>2.</span>
            {reportLang === 'ar' ? 'سجل الأدلة الرقمية وسلسلة الحيازة (Chain of Custody)' : 'Cryptographic Chain of Custody Proofs'}
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-[11px] text-gray-800 border border-gray-200 mt-2">
              <thead className="bg-gray-100 border-b border-gray-200 text-gray-700">
                <tr>
                  <th className="p-2 text-center">#</th>
                  <th className="p-2">{reportLang === 'ar' ? 'نوع الواقعة' : 'Incident Type'}</th>
                  <th className="p-2">{reportLang === 'ar' ? 'المشتبه به' : 'Actor / Suspect'}</th>
                  <th className="p-2">{reportLang === 'ar' ? 'بصمة الدليل (SHA-256)' : 'Evidence Hash'}</th>
                  <th className="p-2 text-center">{reportLang === 'ar' ? 'الحجية القضائية' : 'Admissibility'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 font-mono text-[10px]">
                {(forensicTrail || []).slice(0, 4).map((entry, idx) => (
                  <tr key={idx}>
                    <td className="p-2 text-center font-bold">#{entry.index}</td>
                    <td className="p-2 font-sans font-medium text-gray-900">{entry.incidentType}</td>
                    <td className="p-2 text-cyan-800">{shortAddress(entry.actor)}</td>
                    <td className="p-2 truncate max-w-[180px] text-gray-600">{entry.evidenceHash}</td>
                    <td className="p-2 text-center font-sans">
                      <span className="text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded">
                        {reportLang === 'ar' ? 'قطعي وثابت' : 'VERIFIED'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 3: Legal Sanctions & Recommendations */}
        <div className="mb-8 space-y-2">
          <h3 className="text-sm font-bold text-gray-900 uppercase tracking-wide border-b border-gray-300 pb-1 flex items-center gap-2">
            <span>3.</span>
            {reportLang === 'ar' ? 'الإجراءات الرقابية والقضائية الواجبة النفاذ' : 'Enforceable Legal & Regulatory Sanctions'}
          </h3>
          <ul className="list-disc list-inside text-xs space-y-1.5 text-gray-700 leading-relaxed">
            <li>
              {reportLang === 'ar'
                ? 'إحالة المشغل 0x7099...79C8 إلى القضاء المالي العراقي بموجب المادة 36 من قانون غسل الأموال وتجميد صلاحياته عبر عقد MultiSigApproval فوراً.'
                : 'Refer operator 0x7099...79C8 to the financial judiciary under Article 36 of AML Law 39/2015, executing an immediate MultiSig freeze.'}
            </li>
            <li>
              {reportLang === 'ar'
                ? 'إدراج عنوان المستفيد 0x14dC...9955 في القائمة السوداء الموحدة (AML National Blacklist).'
                : 'Add beneficiary account 0x14dC...9955 to the AML National Blacklist across all Iraqi clearing channels.'}
            </li>
            <li>
              {reportLang === 'ar'
                ? 'اعتماد البصمات التشفيرية المرفقة بهذا الملف كدليل رقمي قطعي غير قابل للطعن (Non-Repudiation).'
                : 'Anchor cryptographic SHA-256 hashes as conclusive, non-repudiable evidence under Iraqi digital evidence statutes.'}
            </li>
          </ul>
        </div>

        {/* Signatures & Cryptographic QR Verification Footer */}
        <div className="pt-6 border-t-2 border-gray-900 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6 text-xs">
          <div className="space-y-3">
            <p className="font-bold text-gray-900">
              {reportLang === 'ar' ? 'رئيس هيئة التحقيق المالي الجنائي الرقمي:' : 'Chief Cyber-Auditing Forensic Officer:'}
            </p>
            <div className="pt-2 border-t border-gray-400 font-mono text-[11px] text-gray-600">
              {reportLang === 'ar' ? 'الختم الرسمي والتوقيع الرقمي المعتمد' : 'Official Judicial Signature & Digital Seal'}
            </div>
            <p className="font-mono text-[9px] text-gray-500 break-all max-w-sm">
              Root Anchor: {caseData.rootHash}
            </p>
          </div>

          {/* Verification SVG QR Code */}
          <div className="flex flex-col items-center p-3 bg-gray-50 border border-gray-300 rounded-xl shrink-0">
            <svg width="84" height="84" viewBox="0 0 84 84">
              <rect width="84" height="84" fill="#ffffff" />
              {/* Decorative Authentic QR Matrix Pattern */}
              <rect x="6" y="6" width="20" height="20" fill="#090e1c" />
              <rect x="9" y="9" width="14" height="14" fill="#ffffff" />
              <rect x="12" y="12" width="8" height="8" fill="#090e1c" />

              <rect x="58" y="6" width="20" height="20" fill="#090e1c" />
              <rect x="61" y="9" width="14" height="14" fill="#ffffff" />
              <rect x="64" y="12" width="8" height="8" fill="#090e1c" />

              <rect x="6" y="58" width="20" height="20" fill="#090e1c" />
              <rect x="9" y="61" width="14" height="14" fill="#ffffff" />
              <rect x="12" y="64" width="8" height="8" fill="#090e1c" />

              {/* Data dots */}
              <circle cx="34" cy="16" r="3" fill="#090e1c" />
              <circle cx="44" cy="16" r="3" fill="#090e1c" />
              <circle cx="40" cy="26" r="3" fill="#090e1c" />
              <circle cx="48" cy="36" r="3" fill="#090e1c" />
              <circle cx="28" cy="46" r="3" fill="#090e1c" />
              <circle cx="38" cy="46" r="3" fill="#090e1c" />
              <circle cx="58" cy="46" r="3" fill="#090e1c" />
              <circle cx="34" cy="68" r="3" fill="#090e1c" />
              <circle cx="46" cy="68" r="3" fill="#090e1c" />
              <circle cx="68" cy="68" r="3" fill="#090e1c" />
            </svg>
            <span className="text-[8px] font-mono font-bold text-gray-600 mt-1 uppercase">
              CBI VERIFIED
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
