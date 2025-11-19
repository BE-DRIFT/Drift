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
const { googleSignin } = require('../controllers/googleAuthController');

// Public routes
router.post('/signup', signup);
router.post('/verify-otp', verifyOTP);
router.post('/resend-otp', resendOTP);
router.post('/login', login);
router.post('/google', googleSignin);

// Protected routes
router.get('/me', authenticate, getCurrentUser);

module.exports = router;