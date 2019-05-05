const jwt = require('jsonwebtoken');
const config = require('config');

//a middleware function is just a function that has access to the request and response cycle

module.exports = function (req, res, next) { // we have to run next when we're done so it goes on to the next piece of middleware
    // Get token from header (When we send a request to a protected route, we need to send the token in the header)
    const token = req.header('x-auth-token'); // this is the header key that we want to send along 

    // check if no token
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // Verify token
    try {
        const decoded = jwt.verify(token, config.get('jwtSecret')); // token & secret 
        // set the req.user to the user that's in that decoded token 
        req.user = decoded.user; // we attached user with the id in the payload
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
}