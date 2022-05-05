const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth'); // middleware which checks token
const bcrypt = require('bcryptjs');
const User = require('../../models/User');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get('/', auth, async (req, res) => { // added middleware auth to protect route
    try {
        const user = await User.findById(req.user.id).select('--password'); // exclude password
        res.json(user);
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server Error');
    }
}); 

// @route   POST api/auth
// @desc    Authenticate user & Get token
// @access  Public
router.post(
    '/',
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required').exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { email, password } = req.body;

        try {
            let user = await User.findOne({ email });

            if (!user) { // error if no such user exists
                // Just to maintain same error msg syntax as above
                return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] });
            }

            const isMatch = await bcrypt.compare(password, user.password); // compare pw from req with user's password

            if (!isMatch) {
                // Just to maintain same error msg syntax as above
                return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] });
            }
            
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