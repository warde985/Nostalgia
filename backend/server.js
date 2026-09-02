require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 32 * 1024 * 1024 } // 32MB - أقصى حجم مسموح به من VirusTotal (الخطة المجانية)
});

app.use(cors());
app.use(express.json());

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

// دالة مساعدة تستنى شوية وقت بين كل محاولة فحص
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

app.get("/", function (req, res) {
  res.send("Server is running!");
});

app.get("/api/test", function (req, res) {
  res.json({ message: "API is working!" });
});

// ============================================================
// فحص الروابط - نسخة async (تستخدمها صفحة url-scanner.html القديمة
// اللي بتنتظر analysisId وتعمل polling بنفسها لو احتجتيها لاحقًا)
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
      return res.status(scanResponse.status).json({
        error: "VirusTotal error",
        details: scanData
      });
    }

    res.json({
      analysisId: scanData.data.id,
      url: url
    });

  } catch (error) {
    console.error("Submit-scan error:", error);
    res.status(500).json({ error: "حدث خطأ أثناء إرسال الرابط للفحص" });
  }
});

// ============================================================
// فحص الروابط - نسخة "كل حاجة في طلب واحد" (submit + poll + نتيجة)
// دي اللي بينادي عليها url-scanner.html في الكود الحالي (runScan)
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

    // 1) SUBMIT: بعت الرابط لـ VirusTotal
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

    // 2) POLL: كرر السؤال لحد ما الفحص يخلص
    const MAX_ATTEMPTS = 15;
    const POLL_INTERVAL = 3000; // 3 ثواني بين كل محاولة

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

    // 3) رجّع النتيجة النهائية جاهزة على شكل واحد
    const stats = resultData.data.attributes.stats || {};
    const results = resultData.data.attributes.results || {};

    const engines = Object.values(results).map(function (engine) {
      return {
        name: engine.engine_name,
        category: engine.category,
        result: engine.result
      };
    });

    res.json({
      url: url,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      engines: engines
    });

  } catch (error) {
    console.error("Check-link error:", error);
    res.status(500).json({ error: "حدث خطأ أثناء فحص الرابط" });
  }
});

// ============================================================
// فحص الملفات
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
      url: resultData.meta && resultData.meta.url_info ? resultData.meta.url_info.url : undefined,
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

module.exports = app;
