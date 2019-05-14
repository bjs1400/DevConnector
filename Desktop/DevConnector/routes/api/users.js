const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcrypt.js');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator/check');

const User = require('../../models/User');

// @route    POST api/users
// @desc     Register user
// @access   Public
router.post('/', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
], async (req, res) => { // callback function to run when user visits this url 
    const errors = validationResult(req);
    if (!errors.isEmpty()) { // if there are errors
        return res.status(400).json({ // if there are errors, return them 
            errors: errors.array()
        });
    }

    const { name, email, password } = req.body;

    try {
        // see if user exists
        let user = await User.findOne({ email }); // destructuring 

        if (!user) {
            return res.status(400).json({ errors: [{ msg: 'User already exists' }] }); // ?? 
        }
        // get users gravatar
        const avatar = gravatar.url(email, { // ??
            s: '200', // size
            r: 'pg', // rating
            d: 'mm' // default
        })

        user = new User({ // creates a new instance of a user 
            name,
            email,
            avatar,
            password
        });
        // encrypt password
        const salt = await bcrypt.genSalt(10); // await, we can use anywhere in the function if async 

        user.password = await bcrypt.hash(password, salt); // update our new user's password with encrypted one 

        await user.save();

        const payload = {
            user: {
                id: user.id // from mongodb database
            }
        }

        jwt.sign(payload, config.get('jwtSecret'),
            { expiresIn: 360000 }, (err, token) => { // possible error & the token itself
                if (err) throw err; // ???
                res.json({ token }) // res.json() is similar to res.send()
            });

    } catch (err) {
        console.error(err.message); // ??? 
        res.status(500).send('Server error');
    }

});

module.exports = router;

