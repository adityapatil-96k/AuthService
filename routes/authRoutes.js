const express = require('express');
const router = express.Router();
const { registerUser, verifyOTP, loginUser, logoutUser, refreshToken, requestReset, resetPassword } = require('../controllers/authController');
const { verifyAccessToken } = require('../middlewares/authMiddleware');

router.post('/register', registerUser);

router.post('/verify-otp', verifyOTP);

router.post('/login', loginUser);

router.post('/logout', logoutUser);

router.post('/request-reset', requestReset);

router.post('/reset-password', resetPassword);

router.post('/refresh-token', refreshToken)
router.get('/protected', verifyAccessToken, (req, res) => {
    res.json({ message: 'This is a protected route', userId: req.user.id });
});

module.exports = router;