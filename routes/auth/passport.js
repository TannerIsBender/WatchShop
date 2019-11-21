const {verifyPassword, hashPassword} = require("../utils/utils.js");
const {sqlFetch} = require("../utils/utils.js");
var LocalStrategy = require("passport-local").Strategy;

async function findByEmail(email) {
    const users = await sqlFetch`SELECT*From users WHERE email=${email}`;
    const user = users[0];
    return user;
}

async function saveUser({email, hash, salt, iterations, displayName}) {
    const users = await sqlFetch`
INSERT INTO users(--columns to insert data into[email],[hash],[salt],[iterations],[displayName],[isAdmin])
VALUES(--first row:values for the columns in the list above
${email},${hash},${salt},${iterations},${displayName},${false})
SELECT id FROM users WHERE ID=@@IDENTITY`;
    const user = users[0];
    return user;
}

module.exports = function (passport) {
    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });
    passport.deserializeUser(async function (id, done) {
        try {
            const users = await sqlFetch`SELECT*From users WHERE id=${id}`;
            const user = users[0];
            done(null, user);
        } catch (err) {
            done(err, null);
        }
    });
    passport.use("local-signup", new LocalStrategy({
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: true
    }, async function (req, email, password, done) {
        if (req.body.password !== req.body.passwordConfirmation) {
            done(null, false, req.flash("signupMessage", "The password and confirmation do not match."));
        }
        if (!req.body.displayName || req.body.displayName.length <= 0) {
            done(null, false, req.flash("signupMessage", "The display name must be provided."));
        }
        const user = await findByEmail(email);
        if (user) {
            return done(null, false, req.flash("signupMessage", "That email is already taken."));
        } else {
            const {hash, salt, iterations} = await hashPassword(password);
            var newUser = await saveUser({email, hash, salt, iterations, displayName: req.body.displayName});
            return done(null, newUser);
        }
    }));
    passport.use("local-login", new LocalStrategy({
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: true
    }, async function (req, email, password, done) {
        const user = await findByEmail(email);
        if (!user)
            return done(null, false, req.flash("loginMessage", "No user found with that email."));
        if (!(await verifyPassword(user.hash, user.salt, user.iterations, password)))
            return done(null, false, req.flash("loginMessage", "Oops! Wrong password."));
        return done(null, user);
    }));
};