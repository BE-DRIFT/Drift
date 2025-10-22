const { auth } = require('../config/firebase');
const User = require('../models/User');
const OTP = require('../models/OTP');
const { generateToken } = require('../utils/auth');
const generateOTP = require('../utils/generateOTP');
const { sendOTPEmail } = require('../utils/emailService');
const bcrypt = require('bcryptjs');

// Validation helper functions
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

const validateName = (name) => {
  return name && name.trim().length >= 2;
};

// Clean up pending users and their Firebase accounts
const cleanupPendingUser = async (firebaseUid, email) => {
  try {
    // Delete from Firebase
    await auth.deleteUser(firebaseUid);
    console.log(`✅ Cleaned up Firebase user: ${email}`);
  } catch (error) {
    console.error(`❌ Error cleaning up Firebase user ${email}:`, error);
  }
};

// Hash password for secure storage
const hashPassword = async (password) => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

// Verify password
const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Signup with complete validation
const signup = async (req, res) => {
  let firebaseUid = null;
  
  try {
    const { name, email, password, confirmPassword } = req.body;

    // Validate input fields
    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required: name, email, password, confirmPassword'
      });
    }

    // Validate name
    if (!validateName(name)) {
      return res.status(400).json({
        success: false,
        message: 'Name must be at least 2 characters long'
      });
    }

    // Validate email format
    if (!validateEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    // Validate password
    if (!validatePassword(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character'
      });
    }

    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    // Check if user already exists in MongoDB
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    try {
      // Create user in Firebase
      const firebaseUser = await auth.createUser({
        email: email.toLowerCase(),
        password,
        displayName: name.trim(),
        emailVerified: false
      });
      firebaseUid = firebaseUser.uid;
    } catch (firebaseError) {
      console.error('Firebase creation error:', firebaseError);

      if (firebaseError.code === 'auth/email-already-exists' || firebaseError.code === 'auth/email-already-in-use') {
        return res.status(409).json({
          success: false,
          message: 'User already exists with this email'
        });
      }

      if (firebaseError.code === 'auth/invalid-email') {
        return res.status(400).json({
          success: false,
          message: 'Invalid email address format'
        });
      }

      if (firebaseError.code === 'auth/weak-password') {
        return res.status(400).json({
          success: false,
          message: 'Password is too weak. Must be at least 8 characters with uppercase, lowercase, number and special character'
        });
      }

      return res.status(500).json({
        success: false,
        message: 'Failed to create user account'
      });
    }

    // Hash password for MongoDB storage
    const hashedPassword = await hashPassword(password);

    // Create user in MongoDB as pending
    const user = new User({
      name: name.trim(),
      email: email.toLowerCase(),
      firebaseUid,
      password: hashedPassword, // Store hashed password
      isEmailVerified: false,
      isPending: true
    });

    await user.save();
    console.log(`✅ User saved in MongoDB: ${email}`);

    // Generate OTP
    const otp = generateOTP();
    const otpRecord = new OTP({
      email: email.toLowerCase(),
      otp,
      type: 'signup',
      expiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
    });

    await otpRecord.save();

    // Send OTP email
    const emailSent = await sendOTPEmail(email.toLowerCase(), otp, name.trim());

    res.status(201).json({
      success: true,
      message: emailSent 
        ? 'User created successfully. OTP sent to email.' 
        : 'User created successfully. But failed to send OTP email.',
      data: {
        userId: user._id,
        email: user.email,
        name: user.name,
        isEmailVerified: user.isEmailVerified
        // OTP is NOT included in response for security
      }
    });

  } catch (error) {
    console.error('Signup error:', error);

    // Clean up Firebase user if MongoDB save fails
    if (firebaseUid) {
      await cleanupPendingUser(firebaseUid, req.body.email);
    }

    // MongoDB duplicate key error
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    // MongoDB validation error
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
};

// Verify OTP with enhanced error handling - NOW RETURNS TOKEN AND USER DATA
const verifyOTP = async (req, res) => {
  try {
    const { email, otp, type = 'signup' } = req.body;

    // Validate input
    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Email and OTP are required'
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    if (otp.length !== 6 || !/^\d+$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: 'OTP must be a 6-digit number'
      });
    }

    // Find OTP record
    const otpRecord = await OTP.findOne({
      email: email.toLowerCase(),
      otp,
      type,
      isUsed: false,
      expiresAt: { $gt: new Date() }
    });

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP'
      });
    }

    // Check attempts
    if (otpRecord.attempts >= 3) {
      await OTP.findByIdAndUpdate(otpRecord._id, { isUsed: true });
      return res.status(429).json({
        success: false,
        message: 'Too many failed attempts. Please request a new OTP.'
      });
    }

    // If OTP is correct, mark as used
    if (otpRecord.otp === otp) {
      otpRecord.isUsed = true;
      await otpRecord.save();

      let user;
      
      // Update user verification status if signup
      if (type === 'signup') {
        user = await User.findOneAndUpdate(
          { email: email.toLowerCase() },
          { 
            isEmailVerified: true,
            isPending: false // Remove pending status
          },
          { new: true }
        );

        if (!user) {
          return res.status(404).json({
            success: false,
            message: 'User not found'
          });
        }

        // Verify email in Firebase
        try {
          await auth.updateUser(user.firebaseUid, {
            emailVerified: true
          });
        } catch (firebaseError) {
          console.error('Firebase email verification error:', firebaseError);
        }
      } else {
        // For other OTP types (login, reset-password), just get the user
        user = await User.findOne({ email: email.toLowerCase() });
        
        if (!user) {
          return res.status(404).json({
            success: false,
            message: 'User not found'
          });
        }
      }

      // Generate JWT token
      const token = generateToken({
        userId: user._id,
        email: user.email
      });

      // Return token and user data
      return res.json({
        success: true,
        message: 'OTP verified successfully',
        data: {
          token,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            isEmailVerified: user.isEmailVerified
          }
        }
      });
    } else {
      // OTP is incorrect
      otpRecord.attempts += 1;
      await otpRecord.save();
      
      const attemptsLeft = 3 - otpRecord.attempts;
      
      return res.status(400).json({
        success: false,
        message: `Invalid OTP. ${attemptsLeft > 0 ? `${attemptsLeft} attempts left` : 'No attempts left'}`,
        attemptsLeft: attemptsLeft > 0 ? attemptsLeft : 0
      });
    }

  } catch (error) {
    console.error('OTP verification error:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation failed'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error during OTP verification'
    });
  }
};

// Resend OTP with error handling
const resendOTP = async (req, res) => {
  try {
    const { email, type = 'signup' } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found with this email'
      });
    }

    // Check if there's a recent OTP that hasn't expired
    const recentOTP = await OTP.findOne({
      email: email.toLowerCase(),
      type,
      isUsed: false,
      expiresAt: { $gt: new Date() },
      createdAt: { $gt: new Date(Date.now() - 1 * 60 * 1000) } // Within 1 minute
    });

    if (recentOTP) {
      return res.status(429).json({
        success: false,
        message: 'Please wait before requesting a new OTP'
      });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpRecord = new OTP({
      email: email.toLowerCase(),
      otp,
      type,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
    });

    await otpRecord.save();

    // Send OTP email
    const emailSent = await sendOTPEmail(email.toLowerCase(), otp, user.name);

    res.json({
      success: true,
      message: emailSent 
        ? 'OTP sent successfully to your email'
        : 'OTP generated but failed to send email'
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation failed'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to resend OTP. Please try again.'
    });
  }
};

// Login with proper password verification
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    // Check if user exists in MongoDB and is not pending
    const user = await User.findOne({ 
      email: email.toLowerCase(),
      isPending: false 
    });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found with this email or account not verified'
      });
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email before logging in'
      });
    }

    // Verify password using bcrypt
    const isPasswordValid = await verifyPassword(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Verify Firebase user exists
    let firebaseUser;
    try {
      firebaseUser = await auth.getUserByEmail(email.toLowerCase());
    } catch (firebaseError) {
      console.error('Firebase user fetch error:', firebaseError);
      
      if (firebaseError.code === 'auth/user-not-found') {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      return res.status(500).json({
        success: false,
        message: 'Authentication service unavailable'
      });
    }

    // Generate JWT token
    const token = generateToken({
      userId: user._id,
      email: user.email
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          isEmailVerified: user.isEmailVerified
        }
      }
    });

  } catch (error) {
    console.error('Login error:', error);

    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation failed'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
};

// Get current user
const getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password -firebaseUid');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        user
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    
    if (error.name === 'CastError') {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to fetch user data'
    });
  }
};

module.exports = {
  signup,
  verifyOTP,
  resendOTP,
  login,
  getCurrentUser
};