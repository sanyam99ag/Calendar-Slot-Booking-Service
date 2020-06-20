const express = require('express')
const mongoose = require('mongoose')
const bodyparser = require('body-parser');
const bcrypt = require('bcryptjs')
const user = require('./modals.js')
const passport = require('passport')
const session = require('express-session')
const cookieParser = require('cookie-parser')
const flash = require('connect-flash')

// const { Strategy } = require('passport-local')


const app = express();
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public'));


// using Bodyparser for getting form data
app.use(express.urlencoded({ extended: true }))

// using cookie-parser and session 
app.use(cookieParser('secret'));
app.use(session({
    secret: 'secret',
    maxAge: 3600000, //which is around 2 weeks
    resave: true,
    saveUninitialized: true,
}));

// Using passport for authentications 
app.use(passport.initialize());
app.use(passport.session());

// Using flash for flash messages 
app.use(flash());

// MIDDLEWARES
// Global variable
app.use(async (req, res, next) => {
    res.locals.success_message = req.flash('success_message');
    res.locals.error_message = req.flash('error_message');
    res.locals.error = req.flash('error');
    next();
});

// Check if user is authenticated and clear cache accordingly
const checkAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
        return next();
    } else {
        res.redirect('/login');
    }
}

// mongoose connection
mongoose.connect('mongodb://localhost/nodeAuthentication', {
    useNewUrlParser : true,
    useUnifiedTopology: true
}).then(() => console.log('Database connected'));

// Initial Register route
app.get('/', async (req, res) => {
    res.render('register')
})

// Register POST route to get the form data
app.post('/register', async (req, res) => {
    var {email, username, password, confirmpassword} = req.body;
    var err;  

    // if any field is empty
    if(!email || !username || !password || !confirmpassword)
    {
        err = 'Please fill all details!'
        res.render('register', { 'err': err});
    }

    // if password doesn't match
    if( password != confirmpassword)
    {
        err = 'Passwords Don\'t match!'
        res.render('register', { 'err': err, 'email': email, 'username': username});
    }

    // if everything is fine then check for exiting email in db
    if( typeof err == 'undefined')
    {
        const check = await user.exists({email: req.body.email})
        if(check == false)
        {
            bcrypt.genSalt(10, async (err, salt) => {
                if(err) throw err;
                bcrypt.hash(password, salt, async (err, hash) => {
                    if(err) throw err;
                    password = hash;

                    // save new user
                    await user.create( {
                        email,
                        username,
                        password
                    })
                    req.flash('success_message', "Registered Successfully.. Login To Continue..");
                    res.redirect('/login');                    
                });
            });
        }
        else
        {
            console.log('user exists')
            err = 'User with this email already exists!'
            res.render('register', { 'err': err });
        }
        
    } 
})


// PassportJs Authentication Strategy
var localStrategy = require('passport-local').Strategy;
passport.use(new localStrategy({ usernameField: 'email' }, async (email, password, done) => {
    user.findOne({ email: email }, async (err, data) => {
        if (err) throw err;
        if (!data) {
            return done(null, false, { message: "User Doesn't Exists.." });
        }
        bcrypt.compare(password, data.password, async (err, match) => {
            if (err) {
                return done(null, false);
            }
            if (!match) {
                return done(null, false, { message: "Password Doesn't Match" });
            }
            if (match) {
                return done(null, data);
            }
        });
    });
}));

passport.serializeUser(function (user, cb) {
    cb(null, user.id);
});

passport.deserializeUser(function (id, cb) {
    user.findById(id, function (err, user) {
        cb(err, user);
    });
});

// Login get route
app.get('/login', async (req, res) => {
    res.render('login');
})

// Login post route
app.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        failureRedirect: '/login',
        successRedirect: '/success',
        failureFlash: true,
    })(req, res, next);
});

// Success route
app.get('/success', checkAuthenticated , async (req, res) => {
    res.render('success', { 'user': req.user });
});

// Logout route
app.get('/logout', async (req, res) => {
    req.logout();
    res.redirect('/login');
})


app.listen(5000, () => console.log('Listening to the port 5000'));