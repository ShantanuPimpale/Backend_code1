// auth.middleware.js
const jwt = require('jsonwebtoken');
const { ApiError } = require('./error.middleware');
const logger = require('../config/logger');
const User = require('../model/user.model');
const TokenBlacklist = require('../model/blackListToken.model');

const SECRET_KEY = process.env.JWT_SECRET || 'yourSecretKey';

const authenticateToken = async (req, res, next) => {
    try {
        // Get authorization header
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN format

        if (!token) {
            throw new ApiError(401, 'Authentication required');
        }

        // Verify token
        const decoded = jwt.verify(token, SECRET_KEY);

        // Check if user exists and is active
        const user = await User.findById(decoded.id, { password: 0 });

        if (!user) {
            logger.warn(`Token authentication failed: User not found - ID ${decoded.id}`);
            throw new ApiError(401, 'Invalid authentication token');
        }

        if (user.status !== 'active') {
            logger.warn(`Token authentication failed: Account not active - ID ${decoded.id}`);
            throw new ApiError(403, 'Account is not active');
        }

        // Optional: Check if token is blacklisted
        const isBlacklisted = await TokenBlacklist.findOne({ token });
        if (isBlacklisted) {
            logger.warn(`Token authentication failed: Token blacklisted - User ID ${decoded.id}`);
            throw new ApiError(401, 'Token has been revoked');
        }

        // Set user info in request object
        req.user = {
            id: user._id,
            status: user.status
        };

        // Token is valid, proceed
        next();
    } catch (error) {
        // Handle JWT specific errors
        if (error.name === 'JsonWebTokenError') {
            return next(new ApiError(401, 'Invalid token'));
        }

        if (error.name === 'TokenExpiredError') {
            return next(new ApiError(401, 'Token expired'));
        }

        // If it's already an ApiError, just pass it on
        if (error instanceof ApiError) {
            return next(error);
        }

        // Handle other errors
        logger.error('Authentication middleware error', {
            error: error.message,
            stack: error.stack
        });

        next(new ApiError(500, 'Authentication failed'));
    }
};

module.exports = { authenticateToken };