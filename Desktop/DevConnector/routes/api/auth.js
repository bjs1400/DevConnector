const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator/check');

const User = require('../../models/User');

// @route    GET api/auth
// @desc     Test route
// @access   Protected
router.get('/', auth, async (req, res) => { // this route is now protected
    try {
        const user = await User.findById(req.user.id).select('-password'); // will leave off password in the data
        res.json(user); // our redux store is going to later have a state with this stuff in it 
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route    POST api/auth
// @desc     Authenticate user & get token; we go here when we log in 
// @access   Public
router.post('/', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password required').exists()
], async (req, res) => { // callback function to run when user visits this url 
    const errors = validationResult(req);
    if (!errors.isEmpty()) { // if there are errors
        return res.status(400).json({ // if there are errors, return them 
            errors: errors.array()
        });
    }

    const { email, password } = req.body;

    try {
        // see if user exists
        let user = await User.findOne({ email }); // destructuring 

        if (!user) {
            return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] }); // ?? 
        }

        // compare comes with bcrypt & returns a promise & compares plain text password with encrypted pw
        const isMatch = await bcrypt.compare(password, user.password); // compare plain text password w/ user's password in mongo

        if (!isMatch) {
            return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
        }

        const payload = {
            user: {
                id: user.id // from mongodb database
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), // sign the token 
            { expiresIn: 360000 }, (err, token) => { // possible error & the token itself
                if (err) throw err; // ???
                res.json({ token }) // res.json() is similar to res.send() & returns the token 
            });

    } catch (err) {
        console.error(err.message); // ??? 
        res.status(500).send('Server error');
    }

});

module.exports = router;