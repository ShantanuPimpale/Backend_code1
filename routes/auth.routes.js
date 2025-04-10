// auth.routes.js
const express = require('express');
const router = express.Router();
const authController = require('../controller/auth.controller');
const { authenticateToken } = require('../middleware/auth.middleware');

// Local authentication routes
router.post('/login', authController.loginUser);
router.post('/logout', authenticateToken, authController.logoutUser);

// Google OAuth routes
router.get('/google', authController.handleGoogleAuth);
router.get('/google/callback', authController.handleGoogleCallback);

// LinkedIn OAuth routes
router.get('/linkedin', authController.handleLinkedInAuth);
router.get('/linkedin/callback', authController.handleLinkedInCallback);

module.exports = router;