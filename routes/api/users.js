const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const User = require('../../models/User'); 

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post('/',
    [
        check('name', 'Name is required')
            .not()
            .isEmpty(),
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Please enter a password with 6 or more characters')
            .isLength({ min: 6 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { name, email, password } = req.body;

        try {
            let user = await User.findOne({ email });

            if (user) { // should not be able to find existing user with same email
                // Just to maintain same error msg syntax as above
                return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
            }

            const avatar = gravatar.url(email, {
                s: '200', // size
                r: 'pg',  // rating: PG
                d: 'mm'   // default
            })

            user = new User({
                name,
                email,
                avatar,
                password
            });

            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            await user.save();

            const payload = {
                user: {
                    id: user.id // mongodb uses _id, but mongoose abstracts it to id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'), // secret
                { expiresIn: 360000 },  // in seconds
                (err, token) => {       // we either get err or token - handle accordingly
                    if (err) throw err;
                    res.json({ token });
                }
            );

        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }
        
    }
);

module.exports = router;