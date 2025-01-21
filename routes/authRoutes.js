const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

const generateTokens = (username) => {
  const accessToken = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '3h' });
  const refreshToken = jwt.sign({ username }, process.env.JWT_REFRESH_SECRET, { expiresIn: '3d' });
  return { accessToken, refreshToken };
};

router.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username is already taken." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ username, password: hashedPassword, email });
    await user.save();

    return res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error." });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "Invalid username or password." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid username or password." });
    }

    const { accessToken, refreshToken } = generateTokens(username);

    return res.status(200).json({
      message: "Login successful!",
      username,
      accessToken,
      refreshToken, 
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error." });
  }
});

router.post('/refresh-token', (req, res) => {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token required." });
  }

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired refresh token." });
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.username);

    res.status(200).json({
      accessToken,
      refreshToken: newRefreshToken, 
    });
  });
});

module.exports = router;
