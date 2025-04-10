// auth.controller.js
const authService = require('../services/auth.service');
const logger = require('../config/logger');
const { ApiError } = require('../middleware/error.middleware');
const passport = require('passport');

const loginUser = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            throw new ApiError(400, 'Email and password are required');
        }

        // Get IP and user agent for logging purposes
        const ipAddress = req.ip || req.connection.remoteAddress;
        const deviceInfo = req.headers['user-agent'];

        logger.info(`Login attempt for email: ${email.substring(0, 3)}...`);

        // Attempt login
        const { user, token } = await authService.loginUser(email, password, ipAddress, deviceInfo);

        // Log successful login
        logger.info(`User logged in successfully: ${user.id}`);

        // Return user info and token
        res.status(200).json({
            status: 'success',
            message: 'Login successful',
            data: user,
            token
        });

    } catch (error) {
        // If it's already an ApiError, just pass it on
        if (error instanceof ApiError) {
            return next(error);
        }

        // Log and throw generic error
        logger.error('Login error', {
            error: error.message,
            stack: error.stack
        });

        next(new ApiError(500, 'Authentication failed'));
    }
};

const logoutUser = async (req, res, next) => {
    try {
        // Get user ID from authenticated request
        const userId = req.user.id;

        // Get token if you want to blacklist it (optional)
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN format

        logger.info(`Logout requested for user: ${userId}`);

        // Process logout
        await authService.logoutUser(userId, token);

        logger.info(`User logged out successfully: ${userId}`);

        res.status(200).json({
            status: 'success',
            message: 'Logout successful'
        });

    } catch (error) {
        logger.error('Logout error', {
            error: error.message,
            stack: error.stack,
            userId: req.user?.id
        });

        next(new ApiError(500, 'Logout failed'));
    }
};

const handleGoogleAuth = (req, res, next) => {
    logger.info('Google authentication initiated');
    passport.authenticate('google', {
        scope: ['profile', 'email'],
        session: false
    })(req, res, next);
};

const handleGoogleCallback = (req, res, next) => {
    passport.authenticate('google', {
        failureRedirect: '/login',
        session: false
    }, (err, user) => {
        if (err) {
            logger.error('Google auth callback error', { error: err.message });
            return next(new ApiError(500, 'Authentication failed'));
        }

        if (!user) {
            logger.warn('Google auth failed - no user returned');
            return res.redirect('/login?error=auth_failed');
        }

        logger.info(`Google auth successful for user: ${user.user._id}`);
        res.json({
            status: 'success',
            message: "Google Login Successful",
            data: {
                id: user.user._id,
                status: user.user.status
            },
            token: user.token
        });
    })(req, res, next);
};

const handleLinkedInAuth = (req, res, next) => {
    logger.info('LinkedIn authentication initiated');
    passport.authenticate('linkedin', {
        session: false
    })(req, res, next);
};

const handleLinkedInCallback = (req, res, next) => {
    passport.authenticate('linkedin', {
        failureRedirect: '/login',
        session: false
    }, (err, user) => {
        if (err) {
            logger.error('LinkedIn auth callback error', { error: err.message });
            return next(new ApiError(500, 'Authentication failed'));
        }

        if (!user) {
            logger.warn('LinkedIn auth failed - no user returned');
            return res.redirect('/login?error=auth_failed');
        }

        logger.info(`LinkedIn auth successful for user: ${user.user._id}`);
        res.json({
            status: 'success',
            message: "LinkedIn Login Successful",
            data: {
                id: user.user._id,
                status: user.user.status
            },
            token: user.token
        });
    })(req, res, next);
};

module.exports = {
    loginUser,
    logoutUser,
    handleGoogleAuth,
    handleGoogleCallback,
    handleLinkedInAuth,
    handleLinkedInCallback
};