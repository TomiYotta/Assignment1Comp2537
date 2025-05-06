// server.js
// require("./utils.js"); // Uncomment if you have a utils.js file
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require("joi");
const path = require('path');

const { connectToDatabase } = require('./databaseConnection'); // Import the connect function

const port = process.env.PORT || 3000;
const app = express();

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

// Environment variables (already loaded by dotenv)
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database_for_users = process.env.MONGODB_DATABASE; // DB for user data
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// --- CRITICAL RENDER CONFIGURATION (Check these in Render UI!) ---
// 1. RENDER ENV VARS: NODE_ENV=production (ESSENTIAL)
//    All MONGODB_* vars must be correct.
// 2. ATLAS IP WHITELIST: Render's Outbound IP Address(es) for the DB used by sessions AND users.
// --- END CRITICAL RENDER CONFIGURATION ---

if (!node_session_secret || !mongodb_session_secret || !mongodb_user || !mongodb_password || !mongodb_host || !mongodb_database_for_users) {
    console.error('FATAL ERROR SERVER: Essential environment variables missing. Check .env and Render Environment Variables.');
    process.exit(1);
}

let userCollection; // Will be initialized after DB connection
let dbInstance;     // Will store the connected DB object

app.use(express.urlencoded({ extended: false })); // Parse URL-encoded bodies
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

/* --- Session Configuration --- */
// Sessions will be stored in a 'sessions' collection within the MONGODB_DATABASE
const sessionMongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database_for_users}?retryWrites=true&w=majority`;
console.log(`SERVER: Attempting to configure session store for URL: ${sessionMongoUrl.replace(mongodb_password, '****')}`);

const mongoStore = MongoStore.create({
    mongoUrl: sessionMongoUrl,
    collectionName: 'sessions', // Explicitly name the sessions collection
    crypto: {
        secret: mongodb_session_secret
    },
    touchAfter: 24 * 3600, // time period in seconds
});

mongoStore.on('create', (sessionId) => console.log(`SESSION_STORE_EVENT: Session created in store: ${sessionId}`));
mongoStore.on('update', (sessionId) => console.log(`SESSION_STORE_EVENT: Session updated in store: ${sessionId}`));
mongoStore.on('destroy', (sessionId) => console.log(`SESSION_STORE_EVENT: Session destroyed in store: ${sessionId}`));
mongoStore.on('error', (error) => console.error('SERVER: FATAL SESSION STORE ERROR (connect-mongo):', error));

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false, // Good practice; we use explicit save
    cookie: {
        maxAge: expireTime,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Crucial for HTTPS
        sameSite: 'lax' // Good default for CSRF protection
    }
}));
console.log("SERVER: Express-session middleware configured.");
if (process.env.NODE_ENV === 'production') {
    console.log("SERVER: Cookie 'secure' attribute will be TRUE.");
} else {
    console.log("SERVER: Cookie 'secure' attribute will be FALSE (local development).");
}
/* --- END Session Configuration --- */


// Input Validation Middleware
function validateInput(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            console.error("SERVER: Validation Error:", error.details.map(d => d.message).join(', '));
            // Sending a more user-friendly message, but logging details
            return res.status(400).send(`Invalid input: ${error.details[0].message}. <a href="javascript:history.back()">Go Back</a>`);
        }
        next();
    };
}

// Authentication Check Middleware
function isAuthenticated(req, res, next) {
    console.log(`SERVER: isAuthenticated Check for path: ${req.path}, Session ID: ${req.sessionID}, Authenticated: ${req.session ? req.session.authenticated : 'N/A (no session)'}`);
    if (req.session && req.session.authenticated) {
        console.log(`SERVER: Auth check PASSED for ${req.session.username || 'user'}`);
        return next();
    }
    console.log(`SERVER: Auth check FAILED. Redirecting to /login.`);
    res.redirect('/login');
}

// Root route
app.get('/', (req, res) => {
    let navLinks;
    if (req.session && req.session.authenticated) {
        navLinks = `
            <p>Hello, ${req.session.username}!</p>
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

// Signup form
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

// Signup logic
app.post('/signup',
    validateInput(Joi.object({ // Applying validation
        name: Joi.string().trim().required(),
        email: Joi.string().trim().email().required(),
        password: Joi.string().min(8).required()
    })),
    async (req, res) => {
        const { name, email, password } = req.body;
        console.log(`SERVER: Attempting signup for email: ${email}`);
        try {
            if (!userCollection) {
                console.error("SERVER: userCollection is not initialized during signup!");
                return res.status(500).send('Server configuration error (DB not ready).');
            }
            const existingUser = await userCollection.findOne({ email: email });
            if (existingUser) {
                console.log(`SERVER: Signup attempt: Email ${email} already in use.`);
                return res.status(409).send('Email already in use. <a href="/login">Login</a>');
            }
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const result = await userCollection.insertOne({
                name: name, email: email, password: hashedPassword, createdAt: new Date()
            });
            console.log(`SERVER: User ${email} created in DB. Result ID: ${result.insertedId}`);

            req.session.regenerate(function(err) {
                if (err) {
                    console.error('SERVER: Signup: Session regeneration failed:', err);
                    return res.status(500).send('Error processing signup (session regen).');
                }
                console.log(`SERVER: Signup: Session regenerated. New Session ID: ${req.sessionID}`);
                req.session.authenticated = true;
                req.session.username = name;
                req.session.email = email;
                req.session.userId = result.insertedId;
                console.log(`SERVER: Signup: Session data set for ${name}. Authenticated: ${req.session.authenticated}`);

                req.session.save(function(err) {
                    if (err) {
                        console.error('SERVER: Signup: req.session.save() FAILED:', err);
                        return res.status(500).send('Error saving session after signup.');
                    }
                    console.log(`SERVER: Signup: req.session.save() SUCCEEDED for Session ID: ${req.sessionID}. Redirecting to /parrots...`);
                    res.redirect('/parrots');
                });
            });
        } catch (err) {
            console.error("SERVER: Signup: Overall catch block error:", err);
            res.status(500).send('Error creating user');
        }
    }
);

// Login form
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

// Login logic
app.post('/login',
    validateInput(Joi.object({ // Applying validation
        email: Joi.string().trim().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        const { email, password } = req.body;
        console.log(`SERVER: Attempting login for email: ${email}`);
        try {
            if (!userCollection) {
                console.error("SERVER: userCollection is not initialized during login!");
                return res.status(500).send('Server configuration error (DB not ready).');
            }
            const user = await userCollection.findOne({ email: email });
            if (!user) {
                console.log(`SERVER: Login attempt: User with email ${email} not found.`);
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }

            if (await bcrypt.compare(password, user.password)) {
                req.session.regenerate(function(err) {
                    if (err) {
                        console.error('SERVER: Login: Session regeneration failed:', err);
                        return res.status(500).send('Error processing login (session regen).');
                    }
                    console.log(`SERVER: Login: Session regenerated. New Session ID: ${req.sessionID}`);
                    req.session.authenticated = true;
                    req.session.username = user.name;
                    req.session.email = user.email;
                    req.session.userId = user._id;
                    console.log(`SERVER: Login: Session data set for ${user.name}. Authenticated: ${req.session.authenticated}`);

                    req.session.save(function(err) {
                        if (err) {
                            console.error('SERVER: Login: req.session.save() FAILED:', err);
                            return res.status(500).send('Error saving session after login.');
                        }
                        console.log(`SERVER: Login: req.session.save() SUCCEEDED for Session ID: ${req.sessionID}. Redirecting to /parrots...`);
                        res.redirect('/parrots');
                    });
                });
            } else {
                console.log(`SERVER: Login attempt: Incorrect password for email ${email}.`);
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }
        } catch (err) {
            console.error("SERVER: Login: Overall catch block error:", err);
            res.status(500).send('Login failed');
        }
    }
);

// Protected route
app.get('/parrots', isAuthenticated, (req, res) => {
    console.log(`SERVER: Rendering /parrots page for User: ${req.session.username}, Session ID: ${req.sessionID}`);
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

// Logout route
app.get('/logout', (req, res) => {
    const username = req.session ? req.session.username : 'unknown_user';
    const sessionID = req.sessionID; // req.sessionID will exist even if req.session is null after destroy
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                console.error(`SERVER: Logout Error for Session ID ${sessionID}:`, err);
            } else {
                console.log(`SERVER: User ${username} (Session ID: ${sessionID}) logged out and session destroyed.`);
            }
            // It's good practice to clear the cookie on the client-side as well.
            res.clearCookie('connect.sid', { path: '/' }); // Ensure path matches how it was set
            res.redirect('/');
        });
    } else {
        // This case should ideally not happen if a session was established.
        console.log(`SERVER: Logout attempt with no active session (Session ID: ${sessionID}). Clearing cookie.`);
        res.clearCookie('connect.sid', { path: '/' });
        res.redirect('/');
    }
});


// Fallback 404 (should be after all other specific routes)
app.use((req, res, next) => {
    console.log(`SERVER: 404 Not Found: ${req.method} ${req.originalUrl}`);
    res.status(404).send('Page not found - 404');
});

// Generic Error handling middleware (should be last app.use())
app.use((err, req, res, next) => {
    console.error("SERVER: Unhandled Error in middleware/route:", err.stack);
    res.status(500).send('Something broke on the server!');
});


// --- Initialize Database and Start Server ---
async function startServer() {
    try {
        console.log("SERVER_START: Attempting to connect to database via connectToDatabase()...");
        dbInstance = await connectToDatabase();
        if (!dbInstance) {
            console.error("SERVER_START: connectToDatabase() did not return a valid DB instance. Exiting.");
            process.exit(1);
        }
        userCollection = dbInstance.collection('users'); // Initialize userCollection here
        console.log("SERVER_START: User collection initialized successfully.");

        app.listen(port, () => {
            console.log(`SERVER_START: Node application listening on port ${port}`);
            console.log(`SERVER_START: NODE_ENV: ${process.env.NODE_ENV}`); // Will show 'production' on Render if set
            console.log(`SERVER_START: User DB configured for: ${mongodb_database_for_users} on host ${mongodb_host}`);
            const checkSessionUrl = sessionMongoUrl.replace(mongodb_password, '****');
            console.log(`SERVER_START: Session store configured for URL: ${checkSessionUrl}`);
        });

    } catch (error) {
        console.error("SERVER_START: Failed to initialize database or start the server:", error);
        process.exit(1);
    }
}

startServer();