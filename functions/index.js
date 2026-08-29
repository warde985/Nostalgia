const {setGlobalOptions} = require("firebase-functions");
const {onRequest} = require("firebase-functions/https");
const {defineSecret} = require("firebase-functions/params");

setGlobalOptions({maxInstances: 10});

const virusTotalKey = defineSecret("VIRUSTOTAL_API_KEY");

exports.checkLink = onRequest(
  {
    secrets: [virusTotalKey],
    cors: true,
  },
  async (req, res) => {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({
          error: "Method not allowed",
        });
      }

      const url = req.body.url;

      if (!url) {
        return res.status(400).json({
          error: "من فضلك أدخل رابط",
        });
      }

      const formData = new URLSearchParams();
      formData.append("url", url);

      const response = await fetch(
        "https://www.virustotal.com/api/v3/urls",
        {
          method: "POST",
          headers: {
            "x-apikey": virusTotalKey.value(),
            "Content-Type":
              "application/x-www-form-urlencoded",
          },
          body: formData,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        return res.status(response.status).json({
          error: "VirusTotal error",
          details: data,
        });
      }

      const analysisId = data.data.id;

      let analysis;

      for (let i = 0; i < 10; i++) {
        await new Promise((resolve) =>
          setTimeout(resolve, 2000)
        );

const resultResponse = await fetch(
  `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
  {
    headers: {
      "x-apikey": virusTotalKey.value(),
    },
  }
);;

        analysis = await resultResponse.json();

        const status =
          analysis.data.attributes.status;

        if (status === "completed") {
          break;
        }
      }

      const attributes =
        analysis.data.attributes;

      const stats = attributes.stats;
      const results = attributes.results;

      const engines = Object.entries(results).map(
        ([name, result]) => ({
          name: name,
          category: result.category,
          result: result.result,
        })
      );

      return res.json({
        url: url,
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        engines: engines,
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error: "حدث خطأ أثناء الفحص",
      });
    }
  }
);