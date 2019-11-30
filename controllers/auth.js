const User = require('../models/user');
const jwt = require('jsonwebtoken');  // to generate signed token
const expressJwt = require('express-jwt');  // For authorization check
const { errorHandler } = require('../helpers/dbErrorHandler');

exports.signup = (req, res) => {
    console.log("req.body", req.body);
    const user = new User(req.body);
    user.save((error, user) => {
        if(error) {
            return res.status(400).json({
                error: errorHandler(error)
            });
        }
        user.salt = undefined;
        user.hashed_password = undefined;

        res.json({
            user
        });
    });
};

exports.signin = (req, res) => {
    // find user based on e-mail
    const { email, password } = req.body
    User.findOne({ email }, (err, user) => {    // Find User Based On E-mail
        if(err || !user) {
            return res.status(400).json({
                error: 'User With That E-mail Does Not Exist, Please Sign Up'
            });
        }
        // If User Is Found Make Sure Email and Password Match
        // create authenticate method in User model
        if(!user.authenticate(password)) {
            return res.status(401).json({
                error: 'E-mail and Password Do Not Match'
            });
        }
        //Generate a signed token with userId and secret
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET)
        // Persist the token as 't' in Cookie with Expiry Date
        res.cookie('t', token, { expire: new Date() + 9999 })
        // Return response with user and token to Frontend Client
        const { _id, name, email, role } = user
        return res.json({ token, user: { _id, email, name, role } })
    });
};

exports.signout = (req, res) => {
    res.clearCookie('t');
    res.json({ message: 'SignOut Success!' });
};

exports.requireSignin = expressJwt({   //Uses Cookie Parser
    secret: process.env.JWT_SECRET,
    userProperty: 'auth'
});

exports.isAuth = (req, res, next) => {
    let user = req.profile && req.auth && req.profile._id == req.auth._id;
    if (!user) {
        return res.status(403).json({
            error: 'Access denied'
        });
    }
    next();
};

exports.isAdmin = (req, res, next) => {
    if (req.profile.role === 0) {
        return res.status(403).json({
            error: 'Admin resource! Access denied!'
        });
    }
    next();
};