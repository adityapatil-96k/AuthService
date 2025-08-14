const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendOTPEmail(toEmail, otp, type = 'login') {
  let subject, text;

  if (type === 'reset') {
    subject = 'Password Reset OTP';
    text = `Your OTP for resetting your password is: ${otp}`;
  } else {
    subject = 'Your Login OTP';
    text = `Your OTP for logging in is: ${otp}`;
  }

  const mailOptions = {
    from: `"Calmflect Auth" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject,
    text,
  };

  return transporter.sendMail(mailOptions);
}

module.exports = { sendOTPEmail };