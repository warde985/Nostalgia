require("dotenv").config();

const express = require("express");
const cors = require("cors");
const dns = require("dns").promises;

function toUrlId(url) {
  return Buffer.from(url)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function getDomainInfo(rawUrl) {
  let hostname;
  try {
    hostname = new URL(rawUrl.startsWith("http") ? rawUrl : "https://" + rawUrl).hostname;
  } catch (e) {
    return null;
  }

  const info = {
    ip: null,
    country: null,
    host: null,
    registrar: null,
    created: null,
    age: null
  };

  // 1) IP حقيقي عن طريق DNS
  try {
    const dnsResult = await dns.lookup(hostname);
    info.ip = dnsResult.address;
  } catch (e) {
    console.error("DNS lookup failed:", e.message);
  }

  // 2) بلد ومزود الاستضافة عن طريق الـ IP
  if (info.ip) {
    try {
      const geoRes = await fetch(`https://ipapi.co/${info.ip}/json/`);
      const geoData = await geoRes.json();
      info.country = geoData.country_name || null;
      info.host = geoData.org || null;
    } catch (e) {
      console.error("IP geolocation failed:", e.message);
    }
  }

  // 3) جهة التسجيل وتاريخ الإنشاء عن طريق RDAP (بديل WHOIS الحديث)
  try {
    const rdapRes = await fetch(`https://rdap.org/domain/${hostname}`);
    if (rdapRes.ok) {
      const rdapData = await rdapRes.json();

      const registrarEntity = (rdapData.entities || []).find(function (e) {
        return (e.roles || []).includes("registrar");
      });
      if (registrarEntity && registrarEntity.vcardArray) {
        const vcard = registrarEntity.vcardArray[1];
        const fnField = vcard.find(function (f) { return f[0] === "fn"; });
        if (fnField) info.registrar = fnField[3];
      }

      const registrationEvent = (rdapData.events || []).find(function (e) {
        return e.eventAction === "registration";
      });
      if (registrationEvent) {
        const createdDate = new Date(registrationEvent.eventDate);
        info.created = createdDate.toLocaleDateString("en-US", {
          year: "numeric", month: "long", day: "numeric"
        });
        const ageMs = Date.now() - createdDate.getTime();
        info.age = Math.max(0, Math.floor(ageMs / (365.25 * 24 * 60 * 60 * 1000)));
      }
    }
  } catch (e) {
    console.error("RDAP lookup failed:", e.message);
  }

  return info;
}

const app = express();

app.use(cors());
app.use(express.json());


// اختبار السيرفر
app.get("/", function (req, res) {
  res.send("Server is running!");
});


// اختبار API
app.get("/api/test", function (req, res) {
  res.json({
    message: "API is working!"
  });
});


// فحص الرابط باستخدام VirusTotal
app.post("/api/check-link", async function (req, res) {
  try {
    const url = req.body.url;

    if (!url) {
      return res.status(400).json({
        error: "من فضلك أدخل رابط"
      });
    }

    // إرسال الرابط إلى VirusTotal
    const formData = new URLSearchParams();
    formData.append("url", url);

    const scanResponse = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": process.env.VIRUSTOTAL_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: formData
      }
    );

    const scanData = await scanResponse.json();

    if (!scanResponse.ok) {
      return res.status(scanResponse.status).json({
        error: "VirusTotal error",
        details: scanData
      });
    }

    const analysisId = scanData.data.id;

    // ===== انتظار حقيقي (polling) لحد ما التحليل يخلص فعليًا =====
    const MAX_ATTEMPTS = 10;     // أقصى عدد محاولات
    const POLL_INTERVAL = 2000;  // كل محاولة كل 2 ثانية => أقصى انتظار ~20 ثانية
    let resultData = null;

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      await new Promise(function (resolve) {
        setTimeout(resolve, POLL_INTERVAL);
      });

      const resultResponse = await fetch(
        "https://www.virustotal.com/api/v3/analyses/" + analysisId,
        {
          headers: {
            "x-apikey": process.env.VIRUSTOTAL_API_KEY
          }
        }
      );

      resultData = await resultResponse.json();

      if (!resultResponse.ok) {
        return res.status(resultResponse.status).json({
          error: "Could not get analysis result",
          details: resultData
        });
      }

      // لو التحليل خلص فعليًا، اخرج من حلقة الانتظار على طول
      if (resultData.data && resultData.data.attributes.status === "completed") {
        break;
      }
      // غير كده (لسه "queued" أو "in-progress")، هنكرر المحاولة تاني
    }

    // لو بعد كل المحاولات التحليل لسه ماخلصش
    if (!resultData || !resultData.data || resultData.data.attributes.status !== "completed") {
      return res.status(202).json({
        error: "التحليل لسه شغال، جرب تاني بعد شوية"
      });
    }

    // ===== نجيب التقرير الدائم للرابط (فيه كل المحركات بشكل كامل وأدق) =====
    const urlId = toUrlId(url);
    let urlReport = null;
    let reportAttempts = 0;
    const MIN_ENGINES = 60; // أغلب حسابات VT عندها ~70 محرك فحص

    do {
      const reportResponse = await fetch(
        "https://www.virustotal.com/api/v3/urls/" + urlId,
        {
          headers: {
            "x-apikey": process.env.VIRUSTOTAL_API_KEY
          }
        }
      );

      urlReport = await reportResponse.json();

      if (!reportResponse.ok) {
        return res.status(reportResponse.status).json({
          error: "Could not get URL report",
          details: urlReport
        });
      }

      const resultsCount = Object.keys(
        (urlReport.data && urlReport.data.attributes.last_analysis_results) || {}
      ).length;

      if (resultsCount >= MIN_ENGINES) break;

      await new Promise(function (resolve) {
        setTimeout(resolve, POLL_INTERVAL);
      });
      reportAttempts++;
    } while (reportAttempts < 5);

    const stats = urlReport.data.attributes.last_analysis_stats;
    const results = urlReport.data.attributes.last_analysis_results;

    // أسماء برامج الحماية ونتائجها
    const engines = Object.values(results).map(function (engine) {
      return {
        name: engine.engine_name,
        category: engine.category,
        result: engine.result
      };
    });

    // ===== جيب بيانات النطاق الحقيقية =====
    const domainInfo = await getDomainInfo(url);

    // إرسال النتائج للموقع
    res.json({
      url: url,
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undetected: stats.undetected,
      engines: engines,
      domainInfo: domainInfo
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "حدث خطأ أثناء الفحص"
    });
  }
});


// تشغيل السيرفر - لازم يكون آخر الملف
const PORT = process.env.PORT || 5000;


app.post("/api/check-url", async function (req, res) {
  try {
    const url = req.body.url;

    if (!url) {
      return res.status(400).json({
        error: "URL is required"
      });
    }

    // إرسال الرابط إلى VirusTotal
    const submitResponse = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": process.env.VIRUSTOTAL_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          url: url
        })
      }
    );

    const submitData = await submitResponse.json();

    if (!submitResponse.ok) {
      return res.status(submitResponse.status).json(submitData);
    }

    const analysisId = submitData.data.id;

    // انتظار انتهاء التحليل
    let analysis;

    for (let i = 0; i < 10; i++) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 2000);
      });

      const resultResponse = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: {
            "x-apikey": process.env.VIRUSTOTAL_API_KEY
          }
        }
      );

      analysis = await resultResponse.json();

      if (
        analysis.data &&
        analysis.data.attributes.status === "completed"
      ) {
        break;
      }
    }

    const stats = analysis.data.attributes.stats;
    const results = analysis.data.attributes.results;

    res.json({
      stats: stats,
      results: results
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Server error"
    });
  }
});
app.listen(PORT, function () {
  console.log("Server running on port " + PORT);
});
