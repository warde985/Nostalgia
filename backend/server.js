```js
require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", function (req, res) {
  res.send("Server is running!");
});

app.get("/api/test", function (req, res) {
  res.json({
    message: "API is working!"
  });
});


// ========================================
// تحويل URL إلى VirusTotal URL ID
// ========================================
function getUrlId(url) {
  return Buffer.from(url)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}


// ========================================
// تحويل VirusTotal results إلى engines
// ========================================
function buildEngines(results) {
  return Object.values(results || {}).map(function (engine) {
    return {
      name: engine.engine_name || "Unknown",
      category: engine.category || "undetected",
      result: engine.result || null
    };
  });
}


// ========================================
// CHECK LINK
// ========================================
app.post("/api/check-link", async function (req, res) {

  try {

    const url = req.body.url;

    if (!url) {
      return res.status(400).json({
        error: "من فضلك أدخل رابط"
      });
    }

    if (!process.env.VIRUSTOTAL_API_KEY) {
      return res.status(500).json({
        error: "VirusTotal API key is not configured"
      });
    }


    // ========================================
    // 1. إرسال الرابط إلى VirusTotal
    // ========================================

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


    // ========================================
    // 2. لو الرابط موجود بالفعل
    // ========================================

    if (scanResponse.status === 409) {

      console.log("⚠️ URL already exists in VirusTotal");

      const urlId = getUrlId(url);

      const existingResponse = await fetch(
        "https://www.virustotal.com/api/v3/urls/" + urlId,
        {
          headers: {
            "x-apikey": process.env.VIRUSTOTAL_API_KEY
          }
        }
      );

      const existingData = await existingResponse.json();

      if (!existingResponse.ok) {

        console.error(
          "Failed to get existing URL:",
          existingData
        );

        return res.status(existingResponse.status).json({
          error: "Could not get existing VirusTotal result",
          details: existingData
        });
      }


      const attributes = existingData.data.attributes || {};

      const stats = attributes.last_analysis_stats || {};

      const results = attributes.last_analysis_results || {};

      const engines = buildEngines(results);


      return res.json({

        url: url,

        malicious: stats.malicious || 0,

        suspicious: stats.suspicious || 0,

        harmless: stats.harmless || 0,

        undetected: stats.undetected || 0,

        engines: engines

      });
    }


    // ========================================
    // 3. أي Error تاني من VirusTotal
    // ========================================

    if (!scanResponse.ok) {

      console.error(
        "VirusTotal submit error:",
        scanData
      );

      return res.status(scanResponse.status).json({
        error: "VirusTotal error",
        details: scanData
      });
    }


    // ========================================
    // 4. حصل Scan جديد
    // ========================================

    const analysisId = scanData.data.id;

    console.log(
      "✅ Analysis started:",
      analysisId
    );


    // ========================================
    // 5. ننتظر النتيجة
    // ========================================

    let resultData = null;

    for (let i = 0; i < 10; i++) {

      await new Promise(function (resolve) {
        setTimeout(resolve, 2000);
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

        console.error(
          "VirusTotal analysis error:",
          resultData
        );

        return res.status(resultResponse.status).json({
          error: "Could not get analysis result",
          details: resultData
        });
      }


      const attributes =
        resultData.data &&
        resultData.data.attributes;


      if (
        attributes &&
        attributes.status === "completed"
      ) {

        console.log(
          "✅ VirusTotal analysis completed"
        );

        break;
      }

    }


    // ========================================
    // 6. التأكد إن التحليل اكتمل
    // ========================================

    if (
      !resultData ||
      !resultData.data ||
      !resultData.data.attributes
    ) {

      return res.status(500).json({
        error: "Could not retrieve VirusTotal analysis"
      });
    }


    const stats =
      resultData.data.attributes.stats || {};

    const results =
      resultData.data.attributes.results || {};


    const engines = buildEngines(results);


    // ========================================
    // 7. النتيجة النهائية للـ Frontend
    // ========================================

    return res.json({

      url: url,

      malicious: stats.malicious || 0,

      suspicious: stats.suspicious || 0,

      harmless: stats.harmless || 0,

      undetected: stats.undetected || 0,

      engines: engines

    });


  } catch (error) {

    console.error(
      "❌ Check-link error:",
      error
    );

    return res.status(500).json({
      error: "حدث خطأ أثناء الفحص",
      details: error.message
    });
  }

});


// ========================================
// CHECK URL - endpoint إضافي
// ========================================

app.post("/api/check-url", async function (req, res) {

  try {

    const url = req.body.url;

    if (!url) {
      return res.status(400).json({
        error: "URL is required"
      });
    }

    if (!process.env.VIRUSTOTAL_API_KEY) {
      return res.status(500).json({
        error: "VirusTotal API key is not configured"
      });
    }


    const formData = new URLSearchParams();

    formData.append("url", url);


    const submitResponse = await fetch(
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


    const submitData = await submitResponse.json();


    if (!submitResponse.ok) {

      return res.status(submitResponse.status).json(
        submitData
      );
    }


    const analysisId =
      submitData.data.id;


    let analysis = null;


    for (let i = 0; i < 10; i++) {

      await new Promise(function (resolve) {
        setTimeout(resolve, 2000);
      });


      const resultResponse = await fetch(
        "https://www.virustotal.com/api/v3/analyses/" +
        analysisId,
        {
          headers: {
            "x-apikey": process.env.VIRUSTOTAL_API_KEY
          }
        }
      );


      analysis = await resultResponse.json();


      if (
        analysis.data &&
        analysis.data.attributes &&
        analysis.data.attributes.status === "completed"
      ) {
        break;
      }

    }


    if (
      !analysis ||
      !analysis.data ||
      !analysis.data.attributes
    ) {

      return res.status(500).json({
        error: "Could not retrieve VirusTotal analysis"
      });
    }


    const stats =
      analysis.data.attributes.stats || {};

    const results =
      analysis.data.attributes.results || {};


    res.json({

      stats: stats,

      results: results

    });


  } catch (error) {

    console.error(
      "Check-url error:",
      error
    );

    res.status(500).json({
      error: "Server error"
    });

  }

});


module.exports = app;
```
