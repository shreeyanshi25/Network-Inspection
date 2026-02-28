const mongoose = require("mongoose");

const AlertSchema = new mongoose.Schema({
  src_ip: String,
  dst_ip: String,
  threat_level: String,
  threat_score: Number,
  message: String,

  status: {
    type: String,
    default: "Open" // Open | Investigating | Resolved
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Alert", AlertSchema);