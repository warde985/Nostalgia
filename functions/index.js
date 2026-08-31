require("dotenv").config();

const express = require("express");
const cors = require("cors");

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
    // بدل ما نستنى 2 ثانية ثابتة وناخد نتيجة ناقصة، بنسأل VirusTotal
    // كل 2 ثانية "خلصت ولا لسه؟" لحد ما يقول "completed"، أو لحد ما نوصل لأقصى محاولات.
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

    const stats = resultData.data.attributes.stats;
    const results = resultData.data.attributes.results;

    // أسماء برامج الحماية ونتائجها
    const engines = Object.values(results).map(function (engine) {
      return {
        name: engine.engine_name,
        category: engine.category,
        result: engine.result
      };
    });

    // إرسال النتائج للموقع
    res.json({
      url: url,
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undetected: stats.undetected,
      engines: engines
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
