const mongoose = require("mongoose");

const FlowSchema = new mongoose.Schema({
    src_ip: String,
    dst_ip: String,
    packet_count: Number,
    total_bytes: Number,
    avg_packet_size: Number,
    duration: Number,
    byte_rate: Number,
    packet_rate: Number,

    prediction: { type: String, default: "Normal" },

    // Threat fields
    threat_level: { type: String, default: "Low" },
    threat_score: { type: Number, default: 0 },

    // DPI fields
    dns_query: String,
    http_host: String,
    tls_sni: String,

    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Flow", FlowSchema);