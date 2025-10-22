const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  otp: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['signup', 'login', 'reset-password'],
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 300 },
  },
  attempts: {
    type: Number,
    default: 0
  },
  isUsed: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

otpSchema.index({ email: 1, type: 1, isUsed: 1 });

module.exports = mongoose.model('OTP', otpSchema);