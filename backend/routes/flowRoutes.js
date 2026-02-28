const express = require("express");
const router = express.Router();
const Flow = require("../models/Flow");
const Alert = require("../models/Alert");

// ======================================
// GET ALL FLOWS
// ======================================
router.get("/", async (req, res) => {
  try {
    const flows = await Flow.find().sort({ createdAt: -1 });
    res.json(flows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ======================================
// GET ALL ALERTS
// ======================================
router.get("/alerts", async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ createdAt: -1 });
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ======================================
// POST NEW FLOW
// ======================================
router.post("/", async (req, res) => {
  try {
    const flow = new Flow(req.body);
    const savedFlow = await flow.save();

    // 🚨 ALERT TRIGGER LOGIC
    if (
      savedFlow.threat_level === "High" ||
      savedFlow.threat_level === "Critical"
    ) {
      await Alert.create({
        src_ip: savedFlow.src_ip,
        dst_ip: savedFlow.dst_ip,
        threat_level: savedFlow.threat_level,
        threat_score: savedFlow.threat_score,
        domain:
          savedFlow.dns_query ||
          savedFlow.http_host ||
          savedFlow.tls_sni ||
          "Unknown",

        message: `${savedFlow.threat_level} threat detected from ${savedFlow.src_ip}`
      });

      console.log("🚨 ALERT CREATED");
    }

    res.status(201).json(savedFlow);

  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;