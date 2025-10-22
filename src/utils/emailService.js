const nodemailer = require('nodemailer');

// Create transporter
const createTransporter = () => {
  return nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
    tls: {
      rejectUnauthorized: false
    },
    secure: false,
    requireTLS: true
  });
};

const sendOTPEmail = async (email, otp, name = 'User') => {
  try {
    const transporter = createTransporter();
    
    // For development, log OTP instead of sending email
    if (process.env.NODE_ENV === 'development') {
      console.log(`📧 DEVELOPMENT MODE - OTP for ${email}: ${otp}`);
      console.log(`📧 Email would be sent to: ${email}`);
      console.log(`📧 OTP: ${otp}`);
      console.log(`📧 Name: ${name}`);
      
      // Test if we can actually send email in development
      try {
        const testMailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Your OTP Code - Diploper',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #333;">Diploper Verification</h2>
              <p>Hello ${name},</p>
              <p>Your OTP code for verification is:</p>
              <div style="background: #f4f4f4; padding: 15px; text-align: center; margin: 20px 0;">
                <h1 style="margin: 0; color: #333; letter-spacing: 5px;">${otp}</h1>
              </div>
              <p>This OTP will expire in 5 minutes.</p>
              <p>If you didn't request this code, please ignore this email.</p>
              <br>
              <p>Best regards,<br>Diploper Team</p>
            </div>
          `
        };

        await transporter.sendMail(testMailOptions);
        console.log(`✅ OTP email actually sent to ${email}`);
        return true;
      } catch (emailError) {
        console.log('⚠️  Real email failed, but continuing in development mode');
        console.log(`📧 OTP for ${email}: ${otp}`);
        return true;
      }
    }

    // For production, actually send email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code - Diploper',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Diploper Verification</h2>
          <p>Hello ${name},</p>
          <p>Your OTP code for verification is:</p>
          <div style="background: #f4f4f4; padding: 15px; text-align: center; margin: 20px 0;">
            <h1 style="margin: 0; color: #333; letter-spacing: 5px;">${otp}</h1>
          </div>
          <p>This OTP will expire in 5 minutes.</p>
          <p>If you didn't request this code, please ignore this email.</p>
          <br>
          <p>Best regards,<br>Diploper Team</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ OTP email sent to ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Email sending error:', error);
    
    // Even if email fails, we'll consider it successful for development
    if (process.env.NODE_ENV === 'development') {
      console.log(`⚠️  Email failed but continuing in development mode. OTP: ${otp}`);
      return true;
    }
    
    return false;
  }
};

// Test email connection
const testEmailConnection = async () => {
  try {
    const transporter = createTransporter();
    await transporter.verify();
    console.log('✅ Email server connection established');
    return true;
  } catch (error) {
    console.log('⚠️  Email server connection failed - running in development mode');
    return false;
  }
};

module.exports = { sendOTPEmail, testEmailConnection };