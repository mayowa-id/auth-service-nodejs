/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: User login
 *     description: Authenticates a user and returns an access token and refresh token.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                 refreshToken:
 *                   type: string
 *       400:
 *         description: Invalid email or password
 *       500:
 *         description: Server error
 */

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");
require("dotenv").config();
const rateLimiter = require('../middleware/rateLimit');
const router = express.Router();

const ACCESS_TOKEN_EXPIRY = "15m";
const REFRESH_TOKEN_EXPIRY = "7d";

router.post('/login', rateLimiter, async (req, res) => {});

/**
 * Generate an access token
 */
const generateAccessToken = (user) =>
  jwt.sign(
    { userId: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );

/**
 * Generate a refresh token
 */
const generateRefreshToken = (user) =>
  jwt.sign(
    { userId: user._id },
    process.env.REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );

/**
 * @route POST /auth/register
 * @desc Register a new user
 */
const { body, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');

router.post(
  "/register",
  [
    body("username").trim().escape().isLength({ min: 3 }).withMessage("Username must be at least 3 characters long"),
    body("email").isEmail().withMessage("Invalid email format").normalizeEmail(),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
    body("role").optional().isIn(["user", "admin"]).withMessage("Invalid role"),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }//validate

      let { username, email, password, role } = req.body;
      username = sanitizeHtml(username);
      //sanitize

      const existingUser = await User.findOne({ email }).lean();
      if (existingUser) {
        return res.status(400).json({ message: "Email already in use" });
      }

      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);

      const newUser = new User({
        username,
        email,
        passwordHash,
        role: role || "user",
      });

      await newUser.save();

      res.status(201).json({
        message: "User registered successfully",
        user: { id: newUser._id, email: newUser.email },
      });
    } catch (error) {
      res.status(500).json({ message: "Error registering user", error: error.message });
    }
  }
);

/**
 * @route POST /auth/login
 * @desc User login
 */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    user.refreshToken = refreshToken;
    await user.save();

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({ accessToken, role: user.role, message: "Login successful" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * @route POST /auth/logout
 * @desc Logout user by invalidating refresh token
 */
router.post("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const user = await User.findOne({ refreshToken });

    if (!user) {
      return res.status(400).json({ message: "Invalid refresh token" });
    }

    user.refreshToken = null;
    await user.save();

    res.json({ message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * @route GET /auth/profile
 * @desc Get user profile
 */
router.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-passwordHash");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * @route POST /auth/refresh-token
 * @desc Generate new access and refresh token
 */
router.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token required" });
  }

  try {
    const payload = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    const user = await User.findById(payload.userId);

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    user.refreshToken = newRefreshToken;
    await user.save();

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

/**
 * @route GET /auth/google
 * @desc Google OAuth Login
 */
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

router.get(
  "/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/" }),
  (req, res) => {
    const token = generateAccessToken(req.user);
    res.json({ accessToken: token, message: "Google login successful" });
  }
);

/**
 * @route GET /auth/github
 * @desc GitHub OAuth Login
 */
router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));

router.get(
  "/github/callback",
  passport.authenticate("github", { session: false, failureRedirect: "/" }),
  (req, res) => {
    const token = generateAccessToken(req.user);
    res.json({ accessToken: token, message: "GitHub login successful" });
  }
);

/**
 * @route Middleware to check token blacklist
 */
async function checkBlacklist(req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  const isBlacklisted = await client.get(`blacklist_${token}`);
  if (isBlacklisted) return res.status(403).json({ message: "Token has been revoked" });

  next();
}

module.exports = router;
