const express = require('express')
const mongoose = require('mongoose')
const bodyparser = require('body-parser');

const bcrypt = require('bcryptjs')
const user = require('./models/user.js')
const slot = require('./models/slot.js')
const passport = require('passport')
const session = require('express-session')
const cookieParser = require('cookie-parser')
const flash = require('connect-flash')

// require('dotenv').config({ path: 'dev.env' });
var var_arr = ['Refresh the browser to see your events!']
// const { Strategy } = require('passport-local')


const app = express();
PORT = process.env.PORT || 5000;
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


// Mongoose connection
mongoose.connect(process.env.MONGODB_URI || "mongodb+srv://slot:slotter@cluster0-u4rjh.mongodb.net/SLOTFREE?retryWrites=true&w=majority" , {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Database connected')).catch(err => console.log(err));

// Initial Register GET route
app.get('/', async (req, res) => {
    res.render('register')
})

// Register POST route to get the form data
app.post('/register', async (req, res) => {
    var { email, username, password, confirmpassword } = await req.body;
    var err;
    // if any field is empty
    if (!email || !username || !password || !confirmpassword) {
        err = 'Please fill all details!'
        res.render('register', { 'err': err });
    }
    // if password doesn't match
    else if (password != confirmpassword) {
        err = 'Passwords Don\'t match!'
        res.render('register', { 'err': err, 'email': email, 'username': username });
    }
    // if everything is fine then check for exiting email in db
    else if (typeof err == 'undefined') {
        const check = await user.exists({ email: req.body.email })
        if (check == false) {
            bcrypt.genSalt(10, async (err, salt) => {
                if (err) throw err;
                bcrypt.hash(password, salt, async (err, hash) => {
                    if (err) throw err;
                    password = hash;

                    // save new user
                    await user.create({
                        email,
                        username,
                        password
                    })
                    req.flash('success_message', "Registered Successfully.. Login To Continue..");
                    res.redirect('/login');
                });

            });
        }
        else {
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

// Login POST route
app.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        failureRedirect: '/login',
        successRedirect: '/success',
        failureFlash: true,
    })(req, res, next);
});

// Success GET route
app.get('/success', checkAuthenticated, async (req, res) => {
    res.render('success', { 'user': req.user });
});

// Success POST route to get availabe slot information entered by owner
// Add Slots
app.post('/slot', checkAuthenticated, async (req, res) => {

    const date = req.body.date;
    const time = req.body.time;
    const owner = req.user._id;
    console.log(date, time, owner);
    const newslot = await new slot({ date: date, time: time, owner: owner });
    newslot.save(async (error, savedSlot) => {
        if (error) throw error; //404

        if (savedSlot) {
            user.findById(req.user._id, async (error, foundUser) => {
                if (error) throw error; //404

                foundUser.slots.push(savedSlot);
                foundUser.save(async (error, savedUser) => {
                    if (error) throw error; //404

                    req.flash('success_message', "Slot set to available!");
                    res.redirect('/success');

                });
            });
        }
    });
})

// Slots GET route 
// To get all available slots based on the uniq id of partiular user
app.get("/:uniqid/slots", checkAuthenticated, async (req, res) => {
    user.findById(req.params.uniqid).populate("slots").exec(async (error, foundUser) => {
        if (error) {
            console.log(error);
            return res.redirect('/404')
        }

        if (!foundUser) {
            console.log("Api url does not exist");
            return res.redirect('/404')
        }
        res.render('allslots', { 'user': foundUser.username, 'uid': foundUser._id, slots: foundUser.slots })
    });

})

// Book slot
app.post("/:uniqid/slots/:id", checkAuthenticated, async (req, res) => {
    const { google } = require('googleapis');
    const { OAuth2 } = google.auth
    const oAuth2Client = new OAuth2(process.nextTick.CLIENT_ID, process.nextTick.SECRET)

    oAuth2Client.setCredentials({
        refresh_token: process.env.REFRESH_TOKEN

    })

    const calender = google.calender({ version: 'v3', auth: oAuth2Client })
    eventStartTime = new Date()
    eventStartTime.serDate(eventStartTime.getDa() + 2)

    const eventEndTime = new Date()
    eventEndTime.setDate(eventTime.getDay() + 2)
    eventEndTime.setMinutes(eventEndTime.getMinutes() + 60)

    const event = {
        summary: `${req.body.title}`,
        discription: `${req.body.discription}`,
        colorId: 6,
        start: {
            dateTime: eventStartTime,
        },
        ends: {
            dateTime: eventEndTime,
        },
    }

    calender.freebusy.query({
        resource: {
            timeMin: eventStartTime,
            time: eventEndTime,
            items: [{ id: 'primary' }]  //for primary calender events
        },
    },
        (err, res) => {
            if (err) return console.log('Free Busy Query Error: ', err)

            const eventArr = res.data.calender.primary.busy // if not busy
            if (eventArr.length === 0) {
                return calender.events.insert({
                    calenderId: 'primary', resource: event
                },
                    err => {
                        if (err) return console.log('Error Creating Calender Event: ', err)

                        return console.log('Event Created Successfully!')
                    })
            }
            return console.log('Sorry my schedule is busy')
        }
    )


    slot.findById(req.params.id, async (error, foundSlot) => {
        if (error) {
            console.log(error);
            return res.status(400).json({ success: false, msg: "Something went wrong. Please try again" });
        }
        if (!foundSlot) {
            console.log("Slot with given id not found");
            return res.status(400).json({ success: false, msg: "Please check the slot id" });
        }
        foundSlot.free = false;
        foundSlot.booked_by = req.user._id;
        foundSlot.booked_on = new Date().toUTCString();
        foundSlot.title = req.body.title;
        foundSlot.description = req.body.description;
        foundSlot.save(async (error, savedSlot) => {
            if (error) {
                console.log(error);
                return res.status(400).json({ success: false, msg: "Something went wrong. Please try again" });
            }
            user.findById(req.user._id, async (error, foundUser) => {
                if (error) {
                    console.log(error);
                    return res.status(400).json({ success: false, msg: "Something went wrong. Please try again" });
                }
                foundUser.bookedSlots.push(savedSlot._id);
                foundUser.save(function (error, savedUser) {
                    if (error) {
                        console.log(error);
                        return res.status(400).json({ success: false, msg: "Something went wrong. Please try again" });
                    }
                    return res.status(200).json({ success: true, msg: "Slot booking successful", slot: savedSlot });
                });
            });
        });
    });
})

app.get('/googcal', checkAuthenticated, async (req, res) => {
    res.render('googleCalAuth');

})
// Google Calender integration
app.post('/gogcal', checkAuthenticated, async (req, res) => {
    const tkn = req.body.token
    const fs = require('fs');
    const readline = require('readline');
    const { google } = require('googleapis');

    // If modifying these scopes, delete token.json.
    const SCOPES = ['https://www.googleapis.com/auth/calendar.readonly'];
    // The file token.json stores the user's access and refresh tokens, and is
    // created automatically when the authorization flow completes for the first
    // time.
    const TOKEN_PATH = 'token.json';

    // Load client secrets from a local file.
    fs.readFile('credentials.json', (err, content) => {
        if (err) return console.log('Error loading client secret file:', err);
        // Authorize a client with credentials, then call the Google Calendar API.
        authorize(JSON.parse(content), listEvents);
    });

    /**
     * Create an OAuth2 client with the given credentials, and then execute the
     * given callback function.
     * @param {Object} credentials The authorization client credentials.
     * @param {function} callback The callback to call with the authorized client.
     */
    function authorize(credentials, callback) {
        const { client_secret, client_id, redirect_uris } = credentials.installed;
        const oAuth2Client = new google.auth.OAuth2(
            client_id, client_secret, redirect_uris[0]);

        // Check if we have previously stored a token.
        fs.readFile(TOKEN_PATH, (err, token) => {
            if (err) return getAccessToken(oAuth2Client, callback);
            oAuth2Client.setCredentials(JSON.parse(token));
            callback(oAuth2Client);
        });
    }

    /**
     * Get and store new token after prompting for user authorization, and then
     * execute the given callback with the authorized OAuth2 client.
     * @param {google.auth.OAuth2} oAuth2Client The OAuth2 client to get token for.
     * @param {getEventsCallback} callback The callback for the authorized client.
     */
    function getAccessToken(oAuth2Client, callback) {
        oAuth2Client.getToken(tkn, (err, token) => {
            if (err) return console.error('Error retrieving access token', err);
            oAuth2Client.setCredentials(token);
            // Store the token to disk for later program executions
            fs.writeFile(TOKEN_PATH, JSON.stringify(token), (err) => {
                if (err) return console.error(err);
                console.log('Token stored to', TOKEN_PATH);
            });
            callback(oAuth2Client);
        });
    }

    /**
     * Lists the next 10 events on the user's primary calendar.
     * @param {google.auth.OAuth2} auth An authorized OAuth2 client.
     */
    function listEvents(auth) {
        async function fun() {
            const calendar = await google.calendar({ version: 'v3', auth });
            calendar.events.list({
                calendarId: 'primary',
                timeMin: (new Date()).toISOString(),
                maxResults: 10,
                singleEvents: true,
                orderBy: 'startTime',
            }, (err, res) => {
                if (err) return console.log('The API returned an error: ' + err);
                const events = res.data.items;
                if (events.length) {
                    console.log('Upcoming 10 events:', events);
                    events.map((event, i) => {
                        var_arr.push(event)
                    });
                } else {
                    console.log('No upcoming events found.');
                }
            });
        }

        fun()
    }
    res.send(var_arr)
})

// Logout GET route
app.get('/logout', async (req, res) => {
    req.logout();
    res.redirect('/login');
})

app.get('/404', async (req, res) => {
    res.render('404')
})


app.listen(PORT, () => console.log(`Listening to the port ${PORT}`));