import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

const LAKERA_GUARD_API_KEY = process.env.LAKERA_GUARD_API_KEY || "";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Route: Intercept and Check with Lakera Guard
  // This endpoint is kept on the server to protect the LAKERA_GUARD_API_KEY
  app.post("/api/audit/check", async (req, res) => {
    const { input_text } = req.body;

    if (!LAKERA_GUARD_API_KEY) {
      return res.status(500).json({ error: "Lakera API Key missing" });
    }

    try {
      // Send to Lakera Guard
      const lakeraResponse = await axios.post(
        "https://api.lakera.ai/v2/guard",
        {
          messages: [{ role: "user", content: input_text }],
        },
        {
          headers: {
            Authorization: `Bearer ${LAKERA_GUARD_API_KEY}`,
          },
        }
      );

      const result = lakeraResponse.data;
      const isFlagged = result.flagged;
      
      let threat_category = "Safe";
      let compliance_tag = "None";
      let risk_score = 0;

      if (isFlagged) {
        const firstResult = result.results?.[0] || {};
        const categories = firstResult.categories || {};
        
        const categoryEntries = Object.entries(categories);
        if (categoryEntries.length > 0) {
          const [topCategory, score] = categoryEntries.sort((a: any, b: any) => b[1] - a[1])[0];
          threat_category = topCategory;
          risk_score = score as number;
        }

        if (threat_category.toLowerCase().includes("pii")) compliance_tag = "PIPEDA";
        else if (threat_category.toLowerCase().includes("jailbreak")) compliance_tag = "AIDA";
        else compliance_tag = "OSFI";
      }

      res.json({
        flagged: isFlagged,
        threat_category,
        compliance_tag,
        risk_score,
      });
    } catch (error: any) {
      console.error("Lakera API Error:", error.response?.data || error.message);
      res.status(500).json({ error: "Security check failed" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
