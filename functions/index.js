require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

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

/**
 * الخطوة 1: إرسال الرابط لـ VirusTotal للفحص.
 * الطلب ده سريع جدًا (بيرجع فورًا بمجرد ما VT يستلم الرابط ويبدأ الفحص في الخلفية)
 * فمفيش أي خطر إنه يتقفل بسبب timeout بتاع Vercel.
 */
app.post("/api/submit-scan", async function (req, res) {
  try {
    const url = req.body.url;

    if (!url) {
      return res.status(400).json({
        error: "من فضلك أدخل رابط"
      });
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

    // بنرجع الـ analysisId فقط، الفرونت إند هو اللي هيسأل عن الحالة بعد كده
    res.json({
      analysisId: scanData.data.id,
      url: url
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "حدث خطأ أثناء إرسال الرابط للفحص"
    });
  }
});

/**
 * الخطوة 2: التحقق من حالة التحليل.
 * الفرونت إند بيستدعي الـ endpoint ده كل كام ثانية (polling) لحد ما status = "completed".
 * كل استدعاء هنا سريع جدًا (أقل من ثانية) لأنه مجرد سؤال عن حالة، مش انتظار فعلي.
 */
app.get("/api/scan-status/:analysisId", async function (req, res) {
  try {
    const analysisId = req.params.analysisId;

    const resultResponse = await fetch(
      VT_BASE + "/analyses/" + analysisId,
      {
        headers: {
          "x-apikey": VT_API_KEY
        }
      }
    );

    const resultData = await resultResponse.json();

    if (!resultResponse.ok) {
      // معالجة خاصة لتجاوز الحد المسموح من الطلبات
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

    // لسه شغال - رجّع الحالة بس من غير تفاصيل
    if (status !== "completed") {
      return res.json({
        status: status
      });
    }

    // خلص فعليًا - رجّع النتيجة الكاملة
    const stats = resultData.data.attributes.stats;
    const results = resultData.data.attributes.results;

    const engines = Object.values(results).map(function (engine) {
      return {
        name: engine.engine_name,
        category: engine.category,
        result: engine.result
      };
    });

    res.json({
      status: "completed",
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undetected: stats.undetected,
      engines: engines
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "حدث خطأ أثناء التحقق من نتيجة الفحص"
    });
  }
});

// تشغيل السيرفر - لازم يكون آخر الملف
const PORT = process.env.PORT || 5000;

app.listen(PORT, function () {
  console.log("Server running on port " + PORT);
});
