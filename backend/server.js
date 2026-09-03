require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 32 * 1024 * 1024 } // 32MB - VirusTotal free plan limit
});

app.use(cors());
app.use(express.json());

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

// ============================================================
// خريطة ترجمة أسماء الدول (من كود ISO للدولة لاسمها بالعربي)
// ============================================================
const COUNTRY_NAMES_AR = {
  US: "الولايات المتحدة", GB: "المملكة المتحدة", DE: "ألمانيا", FR: "فرنسا",
  NL: "هولندا", CA: "كندا", AU: "أستراليا", JP: "اليابان", CN: "الصين",
  IN: "الهند", BR: "البرازيل", RU: "روسيا", SG: "سنغافورة", IE: "أيرلندا",
  SE: "السويد", CH: "سويسرا", IT: "إيطاليا", ES: "إسبانيا", PL: "بولندا",
  FI: "فنلندا", NO: "النرويج", DK: "الدنمارك", BE: "بلجيكا", AT: "النمسا",
  KR: "كوريا الجنوبية", HK: "هونج كونج", TW: "تايوان", ZA: "جنوب أفريقيا",
  AE: "الإمارات العربية المتحدة", SA: "السعودية", EG: "مصر", TR: "تركيا",
  IL: "إسرائيل", MX: "المكسيك", AR: "الأرجنتين", ID: "إندونيسيا",
  VN: "فيتنام", TH: "تايلاند", MY: "ماليزيا", PH: "الفلبين", PK: "باكستان",
  UA: "أوكرانيا", RO: "رومانيا", CZ: "التشيك", PT: "البرتغال", GR: "اليونان",
  HU: "المجر", IS: "آيسلندا", LU: "لوكسمبورج", NZ: "نيوزيلندا", CL: "تشيلي"
};

function translateCountry(countryCode, fallbackName) {
  if (countryCode && COUNTRY_NAMES_AR[countryCode]) return COUNTRY_NAMES_AR[countryCode];
  return fallbackName || "غير معروف";
}

// ============================================================
// جلب معلومات النطاق الحقيقية - بيتنفذ مرة واحدة بس بعد ما
// الفحص يخلص فعليًا (status === "completed")
// ============================================================
async function getDomainInfo(domain) {
  const info = {
    registrar: "غير معروف",
    created: "غير معروف",
    country: "غير معروف",
    ip: "غير معروف",
    host: "غير معروف",
    reputation: "غير معروفة"
  };

  try {
    const ipResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const ipData = await ipResponse.json();
    const ip = ipData.Answer && ipData.Answer[0] ? ipData.Answer[0].data : null;

    if (ip) {
      info.ip = ip;
      const geoResponse = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode,isp`);
      const geoData = await geoResponse.json();
      if (geoData.country) info.country = translateCountry(geoData.countryCode, geoData.country);
      if (geoData.isp) info.host = geoData.isp;
    }
  } catch (error) {
    console.error("Error fetching IP info:", error);
  }

  try {
    const whoisResponse = await fetch(`https://api.whois.vu/?q=${domain}`);
    const whoisData = await whoisResponse.json();
    if (whoisData.registrar) info.registrar = whoisData.registrar;
    if (whoisData.created) {
      const date = new Date(whoisData.created);
      if (date.getFullYear() > 2000) {
        info.created = date.toLocaleDateString('ar-EG', { year: 'numeric', month: 'long', day: 'numeric' });
      }
    }
  } catch (error) {
    console.error("Error fetching WHOIS info:", error);
  }

  return info;
}

app.get("/", function (req, res) {
  res.send("Server is running!");
});

app.get("/api/test", function (req, res) {
  res.json({ message: "API is working!" });
});

// ============================================================
// فحص الروابط - الخطوة 1: إرسال الرابط فقط (سريع جدًا، بلا انتظار)
// ============================================================
app.post("/api/submit-scan", async function (req, res) {
  try {
    const url = req.body.url;

    if (!url) {
      return res.status(400).json({ error: "من فضلك أدخل رابط" });
    }
    if (!VT_API_KEY) {
      return res.status(500).json({ error: "VirusTotal API key is not configured" });
    }

    const formData = new URLSearchParams();
    formData.append("url", url);

    const scanResponse = await fetch(VT_BASE + "/urls", {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: formData
    });

    const scanData = await scanResponse.json();

    if (!scanResponse.ok) {
      return res.status(scanResponse.status).json({ error: "VirusTotal error", details: scanData });
    }

    res.json({ analysisId: scanData.data.id, url: url });

  } catch (error) {
    console.error("Submit-scan error:", error);
    res.status(500).json({ error: "حدث خطأ أثناء إرسال الرابط للفحص" });
  }
});

// ============================================================
// فحص الملفات - الخطوة 1: رفع الملف
// ============================================================
app.post("/api/submit-file-scan", upload.single("file"), async function (req, res) {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "من فضلك اختر ملف للفحص" });
    }
    if (!VT_API_KEY) {
      return res.status(500).json({ error: "VirusTotal API key is not configured" });
    }

    const formData = new FormData();
    const blob = new Blob([req.file.buffer], { type: req.file.mimetype || "application/octet-stream" });
    formData.append("file", blob, req.file.originalname);

    const uploadResponse = await fetch(VT_BASE + "/files", {
      method: "POST",
      headers: { "x-apikey": VT_API_KEY },
      body: formData
    });

    const uploadData = await uploadResponse.json();

    if (!uploadResponse.ok) {
      return res.status(uploadResponse.status).json({ error: "VirusTotal error", details: uploadData });
    }

    res.json({
      analysisId: uploadData.data.id,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      fileType: req.file.mimetype
    });

  } catch (error) {
    console.error("Submit-file-scan error:", error);
    res.status(500).json({ error: "حدث خطأ أثناء رفع الملف للفحص" });
  }
});

// ============================================================
// الخطوة 2 (مشتركة بين الروابط والملفات): التحقق من حالة التحليل
// كل نداء هنا سريع جدًا - ده اللي بيتجنب مشكلة الـ Vercel timeout
// ============================================================
app.get("/api/scan-status/:analysisId", async function (req, res) {
  try {
    if (!VT_API_KEY) {
      return res.status(500).json({ error: "VirusTotal API key is not configured" });
    }

    const analysisId = req.params.analysisId;

    const resultResponse = await fetch(VT_BASE + "/analyses/" + analysisId, {
      headers: { "x-apikey": VT_API_KEY }
    });

    const resultData = await resultResponse.json();

    if (!resultResponse.ok) {
      if (resultResponse.status === 429) {
        return res.status(429).json({ error: "تم تجاوز الحد المسموح من الطلبات، حاول تاني بعد شوية" });
      }
      return res.status(resultResponse.status).json({ error: "Could not get analysis result", details: resultData });
    }

    const status = resultData.data.attributes.status;

    if (status !== "completed") {
      return res.json({ status: status });
    }

    const stats = resultData.data.attributes.stats || {};
    const results = resultData.data.attributes.results || {};

    const engines = Object.values(results).map(function (engine) {
      return { name: engine.engine_name, category: engine.category, result: engine.result };
    });

    // ===== لو التحليل ده لرابط، هات معلومات النطاق دلوقتي بس (مرة واحدة) =====
    const urlInfo = resultData.meta && resultData.meta.url_info ? resultData.meta.url_info : null;
    const fileInfo = resultData.meta && resultData.meta.file_info ? resultData.meta.file_info : null;

    let domainInfo = undefined;
    if (urlInfo && urlInfo.url) {
      let domain = urlInfo.url;
      try { domain = new URL(urlInfo.url).hostname; } catch (e) { /* keep as-is */ }

      domainInfo = await getDomainInfo(domain);

      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      domainInfo.reputation = malicious > 0 ? "سيئة" : (suspicious > 0 ? "متوسطة" : "جيدة");
    }

    res.json({
      status: "completed",
      url: urlInfo ? urlInfo.url : undefined,
      sha256: fileInfo ? fileInfo.sha256 : undefined,
      md5: fileInfo ? fileInfo.md5 : undefined,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      engines: engines,
      domainInfo: domainInfo
    });

  } catch (error) {
    console.error("Scan-status error:", error);
    res.status(500).json({ error: "حدث خطأ أثناء التحقق من نتيجة الفحص" });
  }
});

module.exports = app;
