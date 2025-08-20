const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'yourSecretKey';

app.use(express.json());
app.use(cookieParser());

// Route to login and set token in cookie
app.post('/login', (req, res) => {
  // In real app, validate user credentials here
  const payload = { userId: 1, username: 'kalvian' };
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true, maxAge: 3600000 }); // 1 hour
  res.json({ message: 'Logged in, token set in cookie.' });
});

// Middleware to verify token
function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
const encrypt = (payload) => {
  // encrypt the payload and return token
}

const decrypt = (token) => {
  // return decoded payload
}

module.exports = {
  encrypt,
  decrypt
}
