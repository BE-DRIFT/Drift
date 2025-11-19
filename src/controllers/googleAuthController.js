const { auth } = require('../config/firebase');
const User = require('../models/User');
const { generateToken } = require('../utils/auth');
const bcrypt = require('bcryptjs');

const googleSignin = async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({
        success: false,
        message: 'ID token is required'
      });
    }

    const decodedToken = await auth.verifyIdToken(idToken);
    const { email, name, picture, uid } = decodedToken;

    let user = await User.findOne({ 
      $or: [
        { email: email.toLowerCase() },
        { firebaseUid: uid }
      ]
    });

    if (user) {
      // Update user data if needed
      if (!user.firebaseUid) {
        user.firebaseUid = uid;
        await user.save();
      }
    } else {
      // Create new user with random password
      const randomPassword = Math.random().toString(36).slice(-16) + 'Aa1!';
      const hashedPassword = await bcrypt.hash(randomPassword, 12);

      user = new User({
        name: name || email.split('@')[0],
        email: email.toLowerCase(),
        firebaseUid: uid,
        password: hashedPassword,
        isEmailVerified: true,
        isPending: false
      });

      await user.save();
    }

    // Generate JWT token
    const token = generateToken({
      userId: user._id,
      email: user.email
    });

    res.json({
      success: true,
      message: 'Google sign-in successful',
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
    console.error('Google sign-in error:', error);

    if (error.code === 'auth/id-token-expired') {
      return res.status(401).json({
        success: false,
        message: 'Google token expired'
      });
    }

    if (error.code === 'auth/id-token-revoked') {
      return res.status(401).json({
        success: false,
        message: 'Google token revoked'
      });
    }

    if (error.code === 'auth/invalid-id-token') {
      return res.status(401).json({
        success: false,
        message: 'Invalid Google token'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Google sign-in failed'
    });
  }
};

module.exports = {
  googleSignin
};