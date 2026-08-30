```js
require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());


// ===============================
// Test server
// ===============================

app.get("/", function (req, res) {
  res.send("Server is running!");
});


// ===============================
// Test API
// ===============================

app.get("/api/test", function (req, res) {
  res.json({
    message: "API is working!"
  });
});


// ===============================
// VirusTotal - Check Link
// ===============================

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

    // Send URL to VirusTotal
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

    // Wait for analysis
    await new Promise(function (resolve) {
      setTimeout(resolve, 2000);
    });

    // Get analysis result
    const resultResponse = await fetch(
      "https://www.virustotal.com/api/v3/analyses/" + analysisId,
      {
        headers: {
          "x-apikey": process.env.VIRUSTOTAL_API_KEY
        }
      }
    );

    const resultData = await resultResponse.json();

    if (!resultResponse.ok) {
      return res.status(resultResponse.status).json({
        error: "Could not get analysis result",
        details: resultData
      });
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

    res.status(500).json({
      error: "حدث خطأ أثناء الفحص"
    });
  }
});


// ===============================
// VirusTotal - Check URL
// ===============================

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

    // Submit URL to VirusTotal
    const submitResponse = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
```
