const jwt = require('jsonwebtoken');


const SECRET_KEY = process.env.JWT_SECRET || 'yourSecretKey';
const REFRESH_SECRET_KEY = process.env.JWT_REFRESH_SECRET || 'yourRefreshSecretKey';

// Token expiration 
const TOKEN_EXPIRATION = '7d'; 
// Create Access Token
const createToken = (userId) => {
    return jwt.sign({ id: userId }, SECRET_KEY, { expiresIn: TOKEN_EXPIRATION });
};

// Verify Access Token
const verifyToken = (token) => {
    try {
        return jwt.verify(token, SECRET_KEY);
    } catch (error) {
        console.error("Invalid token:", error);
        throw new Error('Token is invalid or expired');
    }
};


module.exports = {
    createToken,
    verifyToken
};
