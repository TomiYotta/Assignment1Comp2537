// require("./utils.js"); // Your original utils if needed
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs'); // Using bcryptjs from your code
const Joi = require("joi");
const path = require('path'); // For express.static

const port = process.env.PORT || 3000;
const app = express();

const saltRounds = 12; // From sample, for bcryptjs
const expireTime = 1 * 60 * 60 * 1000; // 1 hour, matching your cookie's maxAge

/* --- Your Secret Information Section (from your .env) --- */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE; // Your main app DB
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* --- END Secret Information Section --- */

// Validate environment variables (Essential for deployment)
if (!node_session_secret || !mongodb_session_secret || !mongodb_user || !mongodb_password || !mongodb_host || !mongodb_database) {
    console.error('FATAL ERROR: Session secrets or MongoDB connection details missing. Check Render Env Vars & local .env');
    process.exit(1);
}

/* --- Database Connection --- */
// Assuming your databaseConnection.js correctly sets up and exports 'database' client
// Ensure it uses MONGODB_DATABASE for the main connection and adds "?retryWrites=true&w=majority"
const { database } = require('./databaseConnection'); // Your original way
const userCollection = database.db(mongodb_database).collection('users'); // Using your main app DB for users
/* --- END Database Connection --- */


// Middleware to parse URL-encoded bodies (as sent by HTML forms)
// Using extended: false from the sample, though true is often more flexible
app.use(express.urlencoded({ extended: false }));

// Serve static files (CSS, images, client-side JS)
app.use(express.static(path.join(__dirname, 'public')));


/* --- Session Configuration (Adopting sample's MongoStore setup style) --- */
var mongoStore = MongoStore.create({
    // Storing sessions in a 'sessions' collection within your main app DB
    // OR you can specify a different DB for sessions like: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions_db?retryWrites=true&w=majority`
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`, // Pointing to your main DB, sessions will be in a 'sessions' collection there.
    crypto: {
        secret: mongodb_session_secret
    },
    touchAfter: 24 * 3600 // Optional: time period in seconds after which session will be updated even if not modified
});

mongoStore.on('error', function(error) {
    console.error('Session Store Error (connect-mongo):', error);
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false, // Good practice: Don't save new sessions that are not modified
    resave: true,             // FROM SAMPLE: Forces save even if not modified. Can cause race conditions. Test with false later if this works.
    cookie: {
        maxAge: expireTime, // Use the expireTime variable
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Critical for HTTPS deployment
        sameSite: 'lax' // Good default for CSRF protection
    }
}));
/* --- END Session Configuration --- */


// --- Your Routes Adapted ---

// Input Validation Middleware (Your original)
function validateInput(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            console.error("Validation Error:", error.details);
            return res.status(400).send(`Invalid input: ${error.details[0].message}. <a href="javascript:history.back()">Go Back</a>`);
        }
        next();
    };
}

// Authentication Check Middleware (Your original)
function isAuthenticated(req, res, next) {
    console.log(`isAuthenticated Check for path: ${req.path}, Session ID: ${req.sessionID}, Authenticated: ${req.session.authenticated}`);
    if (req.session.authenticated) {
        return next();
    }
    console.log(`isAuthenticated Failed. Redirecting to /login.`);
    res.redirect('/login');
}

// Root route (Your original)
app.get('/', (req, res) => {
    let navLinks;
    if (req.session.authenticated) {
        navLinks = `
            <p>Hello, ${req.session.username} (Name from session)!</p> 
            <a href="/parrots">Parrots Page</a><br>
            <a href="/logout">Logout</a>
        `;
    } else {
        navLinks = `
            <a href="/signup">Sign Up</a><br>
            <a href="/login">Login</a>
        `;
    }
    res.send(`<h1>Home</h1>${navLinks}`);
});

// Signup form (Your original)
app.get('/signup', (req, res) => {
    res.send(`
        <h1>Sign Up</h1>
        <form action="/signup" method="post">
            <input name="name" placeholder="Your Name" required><br>
            <input name="email" type="email" placeholder="Email Address" required><br>
            <input name="password" type="password" placeholder="Password (min 8 chars)" required><br>
            <button type="submit">Submit</button>
        </form>
        <p><a href="/login">Already have an account? Login</a></p>
    `);
});

// Signup logic (Your original, adapted to use 'email' for login identity)
app.post('/signup',
    validateInput(Joi.object({
        name: Joi.string().trim().required(),
        email: Joi.string().trim().email().required(),
        password: Joi.string().min(8).required()
    })),
    async (req, res) => {
        const { name, email, password } = req.body;
        try {
            const existingUser = await userCollection.findOne({ email: email }); // Check by email
            if (existingUser) {
                return res.status(409).send('Email already in use. <a href="/login">Login</a>');
            }
            const hashedPassword = await bcrypt.hash(password, saltRounds); // Using saltRounds from sample
            const result = await userCollection.insertOne({
                name: name, // Storing full name
                email: email, // Storing email
                password: hashedPassword,
                createdAt: new Date()
            });

            // Set session data
            req.session.authenticated = true;
            req.session.username = name; // Store user's name in session for display
            req.session.email = email; // Store user's email in session (optional, if needed later)
            req.session.userId = result.insertedId;
            // req.session.cookie.maxAge = expireTime; // Set by initial config, but sample did it here

            console.log(`Signup successful for ${name} (${email}). Session ID: ${req.sessionID}. Redirecting...`);
            // With resave:true, session should save automatically before redirect
            res.redirect('/parrots');

        } catch (err) {
            console.error("Signup Error:", err);
            res.status(500).send('Error creating user');
        }
    }
);

// Login form (Your original)
app.get('/login', (req, res) => {
    res.send(`
        <h1>Login</h1>
        <form action="/login" method="post">
            <input name="email" type="email" placeholder="Email Address" required><br>
            <input name="password" type="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
        <p><a href="/signup">Don't have an account? Sign Up</a></p>
    `);
});

// Login logic (Your original, adapted to use 'email')
app.post('/login',
    validateInput(Joi.object({ // Using your Joi validation
        email: Joi.string().trim().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        const { email, password } = req.body;
        try {
            const user = await userCollection.findOne({ email: email }); // Find by email
            if (!user) {
                console.log(`Login attempt: User with email ${email} not found.`);
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }

            if (await bcrypt.compare(password, user.password)) {
                req.session.authenticated = true;
                req.session.username = user.name; // Store user's name
                req.session.email = user.email;   // Store user's email
                req.session.userId = user._id;
                // req.session.cookie.maxAge = expireTime; // Set by initial config, but sample did it here

                console.log(`Login successful for ${user.name} (${user.email}). Session ID: ${req.sessionID}. Redirecting...`);
                // With resave:true, session should save automatically before redirect
                res.redirect('/parrots');
            } else {
                console.log(`Login attempt: Incorrect password for email ${email}.`);
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }
        } catch (err) {
            console.error("Login Error:", err);
            res.status(500).send('Login failed');
        }
    }
);

// Protected route (Your original)
app.get('/parrots', isAuthenticated, (req, res) => {
    console.log(`Rendering /parrots page for User: ${req.session.username}, Session ID: ${req.sessionID}`);
    const images = ['parrot.jpeg', 'parrot2.jpeg', 'parrot3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
    res.send(`
        <h1>Welcome, ${req.session.username}!</h1>
        <p>Enjoy a random parrot:</p>
        <img src="/images/${randomImage}" alt="Random parrot" style="max-width: 500px;">
        <br><br>
        <a href="/logout">Logout</a>
    `);
});

// Logout route (Your original style, sample was simpler)
app.get('/logout', (req, res) => {
    const username = req.session.username;
    const sessionID = req.sessionID;
    req.session.destroy(err => { // Destroys session in store and clears req.session
        if (err) {
            console.error(`Logout Error for Session ID ${sessionID}:`, err);
        } else {
            console.log(`User ${username} (Session ID: ${sessionID}) logged out and session destroyed.`);
        }
        res.clearCookie('connect.sid', { path: '/' }); // Good practice to also clear client-side cookie
        res.redirect('/');
    });
});


// Fallback 404 (Your original)
app.use((req, res, next) => { // Changed to app.use for a catch-all before generic error handler
    res.status(404).send('Page not found - 404');
});

// Generic Error handling middleware (Your original)
app.use((err, req, res, next) => {
    console.error("Unhandled Error:", err.stack);
    res.status(500).send('Something broke!');
});

app.listen(port, () => {
    console.log(`Node application listening on port ${port}`);
    console.log(`NODE_ENV: ${process.env.NODE_ENV}`);
    console.log(`Connecting to user DB: ${mongodb_database} on host ${mongodb_host}`);
    const testSessionUrl = `mongodb+srv://${mongodb_user}:${mongodb_password.substring(0,3)}...@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`;
    console.log(`Session store configured for: ${testSessionUrl}`);
});