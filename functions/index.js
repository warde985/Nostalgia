require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 32 * 1024 * 1024 } // 32MB
});

app.use(cors());
app.use(express.json());

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================
// Helper: Get real domain information
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
    // 1) Get domain IP from Google DNS
    const ipResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const ipData = await ipResponse.json();
    const ip = ipData.Answer && ipData.Answer[0] ? ipData.Answer[0].data : null;
    
    if (ip) {
      info.ip = ip;

      // 2) Get IP info from ip-api.com
      const geoResponse = await fetch(`http://ip-api.com/json/${ip}?fields=country,isp`);
      const geoData = await geoResponse.json();
      
      if (geoData.country) info.country = geoData.country;
      if (geoData.isp) info.host = geoData.isp;
    }
  } catch (error) {
    console.error("Error fetching IP info:", error);
  }

  try {
    // 3) Get Whois info from whois.vu
    const whoisResponse = await fetch(`https://api.whois.vu/?q=${domain}`);
    const whoisData = await whoisResponse.json();
    
    if (whoisData.registrar) info.registrar = whoisData.registrar;
    if (whoisData.created) {
      const date = new Date(whoisData.created);
      if (date.getFullYear() > 2000) {
        info.created = date.toLocaleDateString('ar-EG', { 
          year: 'numeric', 
          month: 'long', 
          day: 'numeric' 
        });
      }
    }
  } catch (error) {
    console.error("Error fetching WHOIS info:", error);
  }

  return info;
}

// ============================================================
// Routes
// ============================================================

app.get("/", function (req, res) {
  res.send("Server is running!");
});

app.get("/api/test", function (req, res) {
  res.json({ message: "API is working!" });
});

// ============================================================
// URL Scanner
// ============================================================
app.post("/api/check-link", async function (req, res) {
  try {
    const url = req.body.url;

    if (!url) {
      return res.status(400).json({ error: "من فضلك أدخل رابط" });
    }

    if (!VT_API_KEY) {
      return res.status(500).json({ error: "VirusTotal API key is not configured" });
    }

    // 1) Submit URL to VirusTotal
    const formData = new URLSearchParams();
    formData.append("url", url);

    const submitResponse = await fetch(VT_BASE + "/urls", {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: formData
    });

    const submitData = await submitResponse.json();

    if (!submitResponse.ok) {
      return res.status(submitResponse.status).json({
        error: "VirusTotal error",
        details: submitData
      });
    }

    const analysisId = submitData.data.id;

    // 2) Poll until scan completes
    const MAX_ATTEMPTS = 15;
    const POLL_INTERVAL = 3000;

    let resultData = null;

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      await sleep(POLL_INTERVAL);

      const analysisResponse = await fetch(VT_BASE + "/analyses/" + analysisId, {
        headers: { "x-apikey": VT_API_KEY }
      });

      const analysisData = await analysisResponse.json();

      if (!analysisResponse.ok) {
        if (analysisResponse.status === 429) {
          await sleep(4000);
          continue;
        }
        return res.status(analysisResponse.status).json({
          error: "Could not get analysis result",
          details: analysisData
        });
      }

      if (analysisData.data.attributes.status === "completed") {
        resultData = analysisData;
        break;
      }
    }

    if (!resultData) {
      return res.status(504).json({
        error: "التحليل أخد وقت أطول من المتوقع، جرب تاني بعد شوية"
      });
    }

    // 3) Extract domain
    let domain = url;
    try {
      domain = new URL(url).hostname;
    } catch (e) {
      domain = url.split('/')[0];
    }

    // 4) Get real domain info
    const domainInfo = await getDomainInfo(domain);

    // 5) Return results
    const stats = resultData.data.attributes.stats || {};
    const results = resultData.data.attributes.results || {};

    const engines = Object.values(results).map(function (engine) {
      return {
        name: engine.engine_name,
        category: engine.category,
        result: engine.result
      };
    });

    // Calculate reputation
    let reputation = "جيدة";
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    if (malicious > 0) {
      reputation = "سيئة";
    } else if (suspicious > 0) {
      reputation = "متوسطة";
    }
    domainInfo.reputation = reputation;

    res.json({
      url: url,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      engines: engines,
      domainInfo: domainInfo
    });

  } catch (error) {
    console.error("Check-link error:", error);
    res.status(500).json({ error: "حدث خطأ أثناء فحص الرابط" });
  }
});

// ============================================================
// File Scanner - Upload
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
      headers: {
        "x-apikey": VT_API_KEY
      },
      body: formData
    });

    const uploadData = await uploadResponse.json();

    if (!uploadResponse.ok) {
      return res.status(uploadResponse.status).json({
        error: "VirusTotal error",
        details: uploadData
      });
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
// File Scanner - Check Status
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
        return res.status(429).json({
          error: "تم تجاوز الحد المسموح من الطلبات، حاول تاني بعد شوية"
        });
      }
      return res.status(resultResponse.status).json({
        error: "Could not get analysis result",
        details: resultData
      });
    }

    const status = resultData.data.attributes.status;

    if (status !== "completed") {
      return res.json({ status: status });
    }

    const stats = resultData.data.attributes.stats || {};
    const results = resultData.data.attributes.results || {};

    const engines = Object.values(results).map(function (engine) {
      return {
        name: engine.engine_name,
        category: engine.category,
        result: engine.result
      };
    });

    const fileInfo = resultData.meta && resultData.meta.file_info ? resultData.meta.file_info : null;

    res.json({
      status: "completed",
      sha256: fileInfo ? fileInfo.sha256 : undefined,
      md5: fileInfo ? fileInfo.md5 : undefined,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      engines: engines
    });

  } catch (error) {
    console.error("Scan-status error:", error);
    res.status(500).json({ error: "حدث خطأ أثناء التحقق من نتيجة الفحص" });
  }
});

// ============================================================
// Start server - MUST be at the END
// ============================================================
const PORT = process.env.PORT || 5000;

app.listen(PORT, function () {
  console.log("🚀 Server running on http://localhost:" + PORT);
  console.log("📡 API test: http://localhost:" + PORT + "/api/test");
  console.log("📡 Check link: http://localhost:" + PORT + "/api/check-link");
  console.log("📡 File scan: http://localhost:" + PORT + "/api/submit-file-scan");
});
