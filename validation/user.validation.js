const Joi = require('joi');

const validateUserRegistration = (data) => {
    const schema = Joi.object({
        first_name: Joi.string().min(1).max(50).required()
            .messages({
                'string.empty': 'First name is required',
                'string.min': 'First name must be at least 1 character long',
                'string.max': 'First name cannot exceed 50 characters',
                'any.required': 'First name is required'
            }),
        last_name: Joi.string().min(1).max(50).required()
            .messages({
                'string.empty': 'Last name is required',
                'string.min': 'Last name must be at least 1 character long',
                'string.max': 'Last name cannot exceed 50 characters',
                'any.required': 'Last name is required'
            }),
        DoB: Joi.date().iso().allow(null, '')
            .messages({
                'date.base': 'Date of birth must be a valid date',
                'date.format': 'Date of birth must be in YYYY-MM-DD format'
            }),
        industry: Joi.string().valid('Healthcare', 'Digital Engineering', 'Life science', 'Pharmacy')
            .messages({
                'any.only': 'Industry must be one of: Healthcare, Digital Engineering, Life science, Pharmacy'
            }),
        email: Joi.string().email().required()
            .messages({
                'string.email': 'Please enter a valid email address',
                'string.empty': 'Email is required',
                'any.required': 'Email is required'
            }),
        password: Joi.string().min(6).required()
            .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{6,}$'))
            .messages({
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 6 characters long',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
                'any.required': 'Password is required'
            }),
        phone_number: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).allow(null, '')
            .messages({
                'string.pattern.base': 'Phone number must be in E.164 format (e.g., +12345678901)'
            }),
        address: Joi.object({
            state: Joi.string().allow(null, ''),
            country: Joi.string().pattern(/^[A-Z]{2}$/).allow(null, '')
                .messages({
                    'string.length': 'Country code must be exactly 2 characters',
                    'string.pattern.base': 'Country code must be in ISO 3166-1 Alpha-2 format (e.g., US, CA)'
                })
        }),
        preferences: Joi.object({
            notification_opt_in: Joi.boolean().default(false)
        })
    });

    return schema.validate(data, { abortEarly: false });
};

module.exports = { validateUserRegistration };