// auth.service.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const userRepository = require('../repository/user.repository');
const { encrypt } = require('../config/encryption');
const logger = require('../config/logger');
const { ApiError } = require('../middleware/error.middleware');

const SECRET_KEY = process.env.JWT_SECRET || 'yourSecretKey';
const TOKEN_EXPIRY = '7d';

const loginUser = async (email, password, ipAddress = null, deviceInfo = null) => {
    try {
        // Create consistent hash for email for lookup
        const emailHash = crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');

        // Find user by email hash
        const user = await userRepository.findUserByEmailHash(emailHash);

        if (!user) {
            logger.warn(`Login failed: No user found for email hash ${emailHash.substring(0, 8)}...`);
            throw new ApiError(401, 'Invalid credentials');
        }

        // Check if user is using social login only
        if (user.provider !== 'local' && !user.password) {
            logger.warn(`Login attempted with password for social auth account: ${user._id}`);
            throw new ApiError(400, `This account uses ${user.provider} authentication`);
        }

        // Check if user account is active
        if (user.status !== 'active') {
            logger.warn(`Login attempt for inactive account: ${user._id}`);
            throw new ApiError(403, 'Account is not active');
        }

        // Verify password
        const isPasswordValid = bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            logger.warn(`Login failed: Invalid password for user ${user._id}`);
            throw new ApiError(401, 'Invalid credentials');
        }

        // Generate JWT token
        const token = generateToken(user._id);

        // Update last login timestamp
        await userRepository.updateUserLastLogin(user._id, ipAddress, deviceInfo);

        return {
            user: {
                id: user._id,
                status: user.status
            },
            token
        };
    } catch (error) {
        // If it's already an ApiError, just rethrow it
        if (error instanceof ApiError) {
            throw error;
        }

        // Log and throw appropriate error
        logger.error('User login failed', {
            error: error.message,
            stack: error.stack
        });

        throw new ApiError(500, error.message || 'Login failed');
    }
};

const logoutUser = async (userId, token = null) => {
    try {
        // Update last activity timestamp
        await userRepository.updateUserLastActivity(userId);

        // Optional: Blacklist the token if you want to invalidate it server-side
        if (token) {
            try {
                const decoded = jwt.verify(token, SECRET_KEY, { ignoreExpiration: true });
                const expiryDate = new Date(decoded.exp * 1000);
                await userRepository.blacklistToken(token, userId, expiryDate);
            } catch (tokenError) {
                logger.warn('Could not decode token for blacklisting', {
                    error: tokenError.message,
                    userId
                });
                // Continue with logout regardless of token decode errors
            }
        }

        return true;
    } catch (error) {
        logger.error('Logout error', {
            error: error.message,
            stack: error.stack,
            userId
        });

        throw new ApiError(500, 'Logout failed');
    }
};

const generateToken = (userId) => {
    try {
        return jwt.sign({ id: userId }, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
    } catch (error) {
        logger.error('Token generation failed', {
            error: error.message,
            stack: error.stack,
            userId
        });
        throw new ApiError(500, 'Authentication token generation failed');
    }
};

const verifyToken = (token) => {
    try {
        return jwt.verify(token, SECRET_KEY);
    } catch (error) {
        logger.error('Token verification failed', {
            error: error.message
        });
        throw new ApiError(401, 'Invalid or expired token');
    }
};

module.exports = {
    loginUser,
    logoutUser,
    generateToken,
    verifyToken
};