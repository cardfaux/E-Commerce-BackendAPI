exports.userSignupValidator = (req, res, next) => {
    req.check('name', 'Name Is Required').notEmpty();
    req.check('email', 'Email Must Be Between 3 and 32 Characters')
        .matches(/.+\@.+\..+/)
        .withMessage('Must Be A Valid E-mail')
        .isLength({
            min: 4, max: 32
        });

    req.check('password', 'Password Is Required').notEmpty();
    req.check('password')
        .isLength({ min: 6 })
        .withMessage('Password Must Be At least 6 Characters')
        .matches(/\d/)
        .withMessage('Password Must Contain A Number');
    const errors = req.validationErrors();
    if(errors) {
        const firstError = errors.map(error => error.msg)[0];
        return res.status(400).json({ error: firstError });
    }
    next();
};