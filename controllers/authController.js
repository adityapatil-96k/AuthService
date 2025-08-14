const bcrypt = require('bcryptjs');
const pool = require('../models/db');
const jwt = require('jsonwebtoken');
const { generateOTP } = require('../utils/otpGenerator');
const { sendOTPEmail } = require('../utils/mailer');

const registerUser = async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Check if user already exists
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    // Insert user into DB
    const newUser = await pool.query(
      'INSERT INTO users (name, email, phone, password_hash) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, email, phone, password_hash]
    );

    const userId = newUser.rows[0].id;

    // // Generate OTP (optional for dev testing or real flow)
    // const otpCode = generateOTP();
    // await pool.query(
    //   'INSERT INTO otp_logs (user_id, otp_code, type) VALUES ($1, $2, $3)',
    //   [userId, otpCode, 'register']
    // );

    // // Send OTP to email
    // await sendOTPEmail(email, otpCode);

    return res.status(201).json({ message: 'User registered successfully. OTP sent to email.' });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ message: 'Server error during registration' });
  }
};



const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check user exists
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Generate OTP and save to DB
    const otp = generateOTP();
    await pool.query(
      'INSERT INTO otp_logs (user_id, otp_code, type) VALUES ($1, $2, $3)',
      [user.id, otp, 'login']
    );

    // Send OTP via email
    await sendOTPEmail(email, otp, 'login');

    // ✅ Tell frontend this is OTP flow
    res.status(200).json({
      otpRequired: true,
      message: 'OTP sent to your email'
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
};

// LOGOUT CONTROLLER
const logoutUser = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token is required' });
  }

  try {
    // Decode token to get userId
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const userId = decoded.userId;

    // Delete the refresh token from the database
    const result = await pool.query(
      'DELETE FROM auth_token WHERE user_id = $1 AND token = $2',
      [userId, refreshToken]
    );

    // If token not found
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Token not found or already logged out' });
    }

    return res.status(200).json({ message: 'Logout successful' });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

const verifyOTP = async (req, res) => {
  const { email, otp, type } = req.body;

  try {
    // 1. Get user
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const user = userResult.rows[0];

    // 2. Fetch OTP for correct type
    const otpResult = await pool.query(
      `SELECT * FROM otp_logs WHERE user_id = $1 AND otp_code = $2 AND type = $3 ORDER BY created_at DESC LIMIT 1`,
      [user.id, otp, type]
    );
    if (otpResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const otpEntry = otpResult.rows[0];
    if (otpEntry.is_verified) {
      return res.status(400).json({ message: 'OTP already used' });
    }

    // 3. Mark OTP as used
    await pool.query('UPDATE otp_logs SET is_verified = true WHERE id = $1', [otpEntry.id]);

    // 4. Different logic for login vs reset
    if (type === 'login') {
      // Generate auth tokens
      const accessToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
        expiresIn: '15m',
      });

      const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_REFRESH_SECRET, {
        expiresIn: '7d',
      });

      // ⬇ Insert refresh token into auth_token table
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
      await pool.query(
        'INSERT INTO auth_token (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [user.id, refreshToken, expiresAt]
      );

      // ✅ Return tokens in JSON (mobile-friendly)
      return res.status(200).json({
        message: 'Login successful',
        accessToken,
        refreshToken,
      });

    } else if (type === 'reset') {
      // Generate a temporary password reset token
      const resetToken = jwt.sign(
        { userId: user.id, email: user.email, otpId: otpEntry.id },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );

      return res.status(200).json({
        message: 'OTP verified for password reset',
        resetToken, // frontend will send this to /reset-password
      });
    } else {
      return res.status(400).json({ message: 'Invalid OTP type' });
    }

  } catch (err) {
    console.error('OTP verification error:', err);
    return res.status(500).json({ message: 'Server error during OTP verification' });
  }
};


const refreshToken = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token is required' });
  }

  try {
    // 1. Verify refresh token signature
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const userId = decoded.userId;

    // 2. Check if token exists in database and is not expired
    const result = await pool.query(
      `SELECT * FROM auth_token WHERE user_id = $1 AND token = $2 AND expires_at > NOW()`,
      [userId, refreshToken]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }

    // 3. Generate new access token
    const newAccessToken = jwt.sign({ userId }, process.env.JWT_SECRET, {
      expiresIn: '15m',
    });

    return res.status(200).json({
      message: 'Access token refreshed successfully',
      accessToken: newAccessToken,
    });

  } catch (err) {
    console.error('Refresh token error:', err);
    return res.status(401).json({ message: 'Invalid refresh token' });
  }
};





const requestReset = async (req, res) => {
  const { email } = req.body;

  try {
    // Step 1: Check if user exists
    const userResult = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userId = userResult.rows[0].id;

    // Step 2: Generate OTP
    const otp = generateOTP();

    // Step 3: Insert OTP into otp_logs table
    await pool.query(
      `INSERT INTO otp_logs (user_id, otp_code, type, is_verified, created_at)
       VALUES ($1, $2, 'reset', false, NOW())`,
      [userId, otp]
    );


  
    await sendOTPEmail(email, otp, 'reset');

    // Step 5: Success response
    return res.status(200).json({ message: 'Password reset OTP sent successfully' });

  } catch (error) {
    console.error('Request reset error:', error);
    return res.status(500).json({ message: 'Server error while sending reset OTP' });
  }
};



const resetPassword = async (req, res) => {
  const { resetToken, newPassword } = req.body;

  try {
    // 1. Verify reset token
    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    const { userId, otpId } = decoded;

    // 2. Check if user still exists
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // 3. Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 4. Update password in DB
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, userId]);

    // 5. Respond success
    return res.status(200).json({ message: 'Password reset successfully' });

  } catch (err) {
    console.error('Reset password error:', err);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Reset token expired' });
    }
    return res.status(400).json({ message: 'Invalid or expired reset token' });
  }
};

module.exports = {
  registerUser,
  verifyOTP,
  loginUser,
  logoutUser,
  refreshToken,
  requestReset,
  resetPassword
};
