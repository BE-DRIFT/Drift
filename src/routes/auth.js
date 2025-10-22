const express = require('express');
const router = express.Router();
const {
  signup,
  verifyOTP,
  resendOTP,
  login,
  getCurrentUser
} = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');

// Public routes
router.post('/signup', signup);
router.post('/verify-otp', verifyOTP);
router.post('/resend-otp', resendOTP);
router.post('/login', login);

// Protected routes
router.get('/me', authenticate, getCurrentUser);

module.exports = router;