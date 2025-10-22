const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters long'],
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please provide a valid email address']
  },
  password: {
    type: String,
    required: [true, 'Password is required']
  },
  firebaseUid: {
    type: String,
    required: [true, 'Firebase UID is required'],
    unique: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  isPending: {
    type: Boolean,
    default: true
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  }
}, {
  timestamps: true
});

userSchema.index({ createdAt: 1 }, { 
  expireAfterSeconds: 3600, 
  partialFilterExpression: { isPending: true } 
});

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ firebaseUid: 1 });
userSchema.index({ isPending: 1 });

module.exports = mongoose.model('User', userSchema);