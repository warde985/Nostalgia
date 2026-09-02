require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

app.get("/", function (req, res) {
  res.send("Server is running!");
});

app.get("/api/test", function (req, res) {
  res.json({ message: "API is working!" });
});

/**
 * الخطوة 1: إرسال الرابط لـ VirusTotal.
 * بيرجع فورًا (خلال أقل من ثانية عادةً) بمجرد ما VT يستلم الرابط ويبدأ الفحص
 * في الخلفية عنده. مفيش أي انتظار هنا، فمستحيل يحصل timeout من Vercel.
 */
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

/**
 * الخطوة 2: التحقق من حالة التحليل.
 * الفرونت إند بينادي على الـ endpoint ده كل 3 ثواني تقريبًا لحد ما status = "completed".
 * كل نداء هنا سريع جدًا (أقل من ثانية) - ده اللي بيحل مشكلة الـ timeout.
 * وأهم حاجة: بيتأكد فعليًا إن الحالة "completed" قبل ما يرجع نتيجة،
 * فمش هترجعلك نتيجة ناقصة زي ما كان بيحصل قبل كده.
 */
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

    // ===== لسه شغال - رجّع الحالة بس، من غير نتيجة ناقصة =====
    if (status !== "completed") {
      return res.json({ status: status });
    }

    // ===== خلص فعليًا - دلوقتي بس نرجّع النتيجة الكاملة والدقيقة =====
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
      status: "completed",
      url: resultData.meta && resultData.meta.url_info ? resultData.meta.url_info.url : undefined,
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
