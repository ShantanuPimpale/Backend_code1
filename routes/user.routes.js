// user.routes.js
const express = require('express');
const router = express.Router();
const userController = require('../controller/user.controller');
const { authenticateToken } = require('../middleware/auth.middleware');

// Public routes
router.post('/createUser', userController.registerUser);
router.post('/verify-email', userController.verifyEmail);
router.post('/resend-otp', userController.resendOTP);
// Protected routes - require authentication
router.get('/getUserProfile', authenticateToken, userController.getUserProfile);
router.put('/user/update', authenticateToken, userController.updateUserProfile);
router.put('/change-password', authenticateToken, userController.changePassword);

module.exports = router;