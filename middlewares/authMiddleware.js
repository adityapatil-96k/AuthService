const jwt = require('jsonwebtoken');

// Middleware to protect routes
const verifyAccessToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  // 1. Check if token is present
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access token missing or invalid' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // 2. Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 3. Attach user info to request
    req.user = { id: decoded.userId };
    next();
  } catch (err) {
    console.error('Access token verification error:', err);
    return res.status(403).json({ message: 'Invalid or expired access token' });
  }
};

module.exports = { verifyAccessToken };