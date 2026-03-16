import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import axios from "axios";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";
const LAKERA_GUARD_API_KEY = process.env.LAKERA_GUARD_API_KEY || "";

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Route: Intercept and Check with Lakera Guard
  app.post("/api/audit/check", async (req, res) => {
    const { input_text, client_name, source_type } = req.body;

    if (!LAKERA_GUARD_API_KEY) {
      return res.status(500).json({ error: "Lakera API Key missing" });
    }

    try {
      // 1. Send to Lakera Guard
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
      
      // Determine threat category and compliance tag based on Lakera response
      // This is a simplified mapping for the MVP
      let threat_category = "None";
      let compliance_tag = "None";
      let risk_score = 0;

      if (isFlagged) {
        // Lakera returns results in 'results' array
        const firstResult = result.results?.[0] || {};
        const categories = firstResult.categories || {};
        
        // Find the highest scoring category
        const categoryEntries = Object.entries(categories);
        if (categoryEntries.length > 0) {
          const [topCategory, score] = categoryEntries.sort((a: any, b: any) => b[1] - a[1])[0];
          threat_category = topCategory;
          risk_score = score as number;
        }

        // Map to compliance tags
        if (threat_category.includes("pii")) compliance_tag = "PIPEDA";
        else if (threat_category.includes("jailbreak")) compliance_tag = "AIDA";
        else compliance_tag = "OSFI";
      }

      // 2. Log to Supabase if flagged (or always log for audit trail)
      // The prompt says: "If Lakera returns flagged: true, block the response and instantly write a new row"
      if (isFlagged) {
        const { error } = await supabase.from("audit_logs").insert([
          {
            client_name: client_name || "Unknown Client",
            source_type: source_type || "User",
            input_text: input_text,
            threat_category: threat_category,
            compliance_tag: compliance_tag,
            risk_score: risk_score,
            is_blocked: true,
          },
        ]);

        if (error) console.error("Supabase Log Error:", error);
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

  // API Route: Get Audit Logs
  app.get("/api/audit/logs", async (req, res) => {
    const { data, error } = await supabase
      .from("audit_logs")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(10);

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  });

  // API Route: Get Stats
  app.get("/api/audit/stats", async (req, res) => {
    const { data, error } = await supabase
      .from("audit_logs")
      .select("is_blocked, compliance_tag");

    if (error) return res.status(500).json({ error: error.message });

    const total = data.length;
    const blocked = data.filter(d => d.is_blocked).length;
    const pipeda = data.filter(d => d.compliance_tag === "PIPEDA").length;
    const aida = data.filter(d => d.compliance_tag === "AIDA").length;

    res.json({
      total,
      blocked,
      health_score: total === 0 ? 100 : Math.max(0, 100 - (blocked / total) * 100),
      pipeda_percent: total === 0 ? 100 : Math.max(0, 100 - (pipeda / total) * 100),
      aida_percent: total === 0 ? 100 : Math.max(0, 100 - (aida / total) * 100),
    });
  });

  // API Route: Behavior Analysis
  app.get("/api/audit/behavior", async (req, res) => {
    const { data, error } = await supabase
      .from("audit_logs")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(50);

    if (error) return res.status(500).json({ error: error.message });

    // Simple anomaly detection logic
    const clientStats: Record<string, { count: number; totalRisk: number }> = {};
    const categoryStats: Record<string, number> = {};
    
    data.forEach(log => {
      // Client frequency
      if (!clientStats[log.client_name]) clientStats[log.client_name] = { count: 0, totalRisk: 0 };
      clientStats[log.client_name].count++;
      clientStats[log.client_name].totalRisk += log.risk_score;

      // Category frequency
      if (log.threat_category !== "None") {
        categoryStats[log.threat_category] = (categoryStats[log.threat_category] || 0) + 1;
      }
    });

    const anomalies = [];

    // Flag 1: High frequency from one client
    Object.entries(clientStats).forEach(([client, stats]) => {
      if (stats.count > 10) {
        anomalies.push({
          type: "High Frequency",
          severity: "Medium",
          description: `Client "${client}" has ${stats.count} interactions in the last 50 logs.`,
          impact: "Potential brute-force or automated probe."
        });
      }
      const avgRisk = stats.totalRisk / stats.count;
      if (avgRisk > 0.6) {
        anomalies.push({
          type: "High Average Risk",
          severity: "High",
          description: `Client "${client}" maintains an average risk score of ${(avgRisk * 100).toFixed(0)}%.`,
          impact: "Persistent malicious behavior detected."
        });
      }
    });

    // Flag 2: Repeated specific threats
    Object.entries(categoryStats).forEach(([category, count]) => {
      if (count > 5) {
        anomalies.push({
          type: "Patterned Attack",
          severity: "High",
          description: `Repeated "${category}" attempts detected (${count} occurrences).`,
          impact: "Targeted exploit attempt identified."
        });
      }
    });

    res.json({
      anomalies,
      summary: {
        total_analyzed: data.length,
        unique_clients: Object.keys(clientStats).length,
        threat_distribution: categoryStats
      }
    });
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
