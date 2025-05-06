// require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require("joi");
const path = require('path');

const port = process.env.PORT || 3000;
const app = express();

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE; // For user data
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// --- CRITICAL RENDER CONFIGURATION (Check these in Render UI!) ---
// 1. RENDER ENV VARS: NODE_ENV=production (ESSENTIAL)
//    All MONGODB_* vars must be correct.
// 2. ATLAS IP WHITELIST: Render's Outbound IP Address(es) for the DB used by sessions.
// --- END CRITICAL RENDER CONFIGURATION ---

if (!node_session_secret || !mongodb_session_secret || !mongodb_user || !mongodb_password || !mongodb_host || !mongodb_database) {
    console.error('FATAL ERROR: Essential environment variables missing. Check Render Environment Variables.');
    process.exit(1);
}

/* --- Database Connection (Users) --- */
// IMPORTANT: Your databaseConnection.js MUST:
// 1. Construct the URI with `?retryWrites=true&w=majority`.
// 2. Call `await client.connect()` before you try to use `database.db()`.
// 3. Log connection success or failure.
// Example of what it might do:
//   const client = new MongoClient(uri);
//   await client.connect();
//   module.exports = { database: client }; // or client.db(mongodb_database)
try {
    const { database } = require('./databaseConnection'); // This should be the connected MongoClient instance
    var userCollection = database.db(mongodb_database).collection('users');
    console.log(`User collection appears to be initialized from database: ${mongodb_database}`);
} catch (e) {
    console.error("FATAL ERROR connecting to main user database or initializing userCollection:", e);
    process.exit(1);
}
/* --- END Database Connection --- */


app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

/* --- Session Configuration --- */
// Option: Use a separate DB for sessions for clarity during debugging
// const session_db_name = 'sessions_comp2537'; // Or stick to mongodb_database
const session_db_name = mongodb_database; // Using main app DB for sessions

const sessionMongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${session_db_name}?retryWrites=true&w=majority`;
console.log(`Attempting to configure session store for URL: ${sessionMongoUrl.replace(mongodb_password, '****')}`);

const mongoStore = MongoStore.create({
    mongoUrl: sessionMongoUrl,
    crypto: {
        secret: mongodb_session_secret
    },
    touchAfter: 24 * 3600, // Optional: time period in seconds
    // autoRemove: 'native' // Recommended for letting MongoDB handle TTL
});

mongoStore.on('create', function (sessionId) {
    console.log(`SESSION STORE EVENT: Session created in store with ID: ${sessionId}`);
});
mongoStore.on('update', function (sessionId) {
    console.log(`SESSION STORE EVENT: Session updated in store with ID: ${sessionId}`);
});
mongoStore.on('destroy', function (sessionId) {
    console.log(`SESSION STORE EVENT: Session destroyed in store with ID: ${sessionId}`);
});
mongoStore.on('error', function(error) {
    // This is critical. If this fires, connect-mongo cannot connect/operate.
    console.error('FATAL SESSION STORE ERROR (connect-mongo):', error);
});
// Test the session store connection explicitly if possible (not a standard API feature of MongoStore directly)
// We rely on the 'error' event and successful session operations.

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false, // Changed back to false - better practice. Save will be explicit.
    cookie: {
        maxAge: expireTime,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));
console.log("Express-session middleware configured.");
if (process.env.NODE_ENV === 'production') {
    console.log("Cookie 'secure' attribute will be TRUE.");
} else {
    console.log("Cookie 'secure' attribute will be FALSE (local development).");
}
/* --- END Session Configuration --- */


// Input Validation Middleware
function validateInput(schema) { /* ... your existing code ... */
    const { error } = schema.validate(req.body);
    if (error) {
        console.error("Validation Error:", error.details);
        return res.status(400).send(`Invalid input: ${error.details[0].message}. <a href="javascript:history.back()">Go Back</a>`);
    }
    next();
}

// Authentication Check Middleware
function isAuthenticated(req, res, next) { /* ... your existing code with logs ... */
    console.log(`isAuthenticated Check for path: ${req.path}, Session ID: ${req.sessionID}, Authenticated: ${req.session.authenticated}`);
    if (req.session.authenticated) {
        console.log(`  Auth check PASSED for ${req.session.username || 'user'}`);
        return next();
    }
    console.log(`  Auth check FAILED. Redirecting to /login.`);
    res.redirect('/login');
}

// Root route
app.get('/', (req, res) => { /* ... your existing code ... */
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

// Signup form
app.get('/signup', (req, res) => { /* ... your existing code ... */
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
    validateInput(Joi.object({ /* ... your existing schema ... */
        name: Joi.string().trim().required(),
        email: Joi.string().trim().email().required(),
        password: Joi.string().min(8).required()
    })),
    async (req, res) => {
        const { name, email, password } = req.body;
        console.log(`Attempting signup for email: ${email}`);
        try {
            if (!userCollection) { // Defensive check
                console.error("userCollection is not initialized during signup!");
                return res.status(500).send('Server configuration error.');
            }
            const existingUser = await userCollection.findOne({ email: email });
            if (existingUser) {
                console.log(`Signup attempt: Email ${email} already in use.`);
                return res.status(409).send('Email already in use. <a href="/login">Login</a>');
            }
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const result = await userCollection.insertOne({
                name: name, email: email, password: hashedPassword, createdAt: new Date()
            });
            console.log(`User ${email} created successfully in DB. Result ID: ${result.insertedId}`);

            // Regenerate session to prevent fixation attacks
            req.session.regenerate(function(err) {
                if (err) {
                    console.error('Signup: Session regeneration failed:', err);
                    return res.status(500).send('Error processing signup (session regen).');
                }
                console.log(`Signup: Session regenerated. New Session ID: ${req.sessionID}`);

                // Set session data AFTER regenerating
                req.session.authenticated = true;
                req.session.username = name;
                req.session.email = email;
                req.session.userId = result.insertedId;
                console.log(`Signup: Session data set for ${name}. Authenticated: ${req.session.authenticated}`);

                // Explicitly save the session
                req.session.save(function(err) {
                    if (err) {
                        console.error('Signup: req.session.save() FAILED:', err);
                        // Even if save fails, the redirect will happen. Client won't get cookie.
                        return res.status(500).send('Error saving session after signup.');
                    }
                    console.log(`Signup: req.session.save() SUCCEEDED for Session ID: ${req.sessionID}. Redirecting to /parrots...`);
                    // If we reach here, the Set-Cookie header *should* be sent.
                    res.redirect('/parrots');
                });
            });
        } catch (err) {
            console.error("Signup: Overall catch block error:", err);
            res.status(500).send('Error creating user');
        }
    }
);

// Login form
app.get('/login', (req, res) => { /* ... your existing code ... */
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
    validateInput(Joi.object({ /* ... your existing schema ... */
        email: Joi.string().trim().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        const { email, password } = req.body;
        console.log(`Attempting login for email: ${email}`);
        try {
            if (!userCollection) { // Defensive check
                console.error("userCollection is not initialized during login!");
                return res.status(500).send('Server configuration error.');
            }
            const user = await userCollection.findOne({ email: email });
            if (!user) {
                console.log(`Login attempt: User with email ${email} not found.`);
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }

            if (await bcrypt.compare(password, user.password)) {
                req.session.regenerate(function(err) {
                    if (err) {
                        console.error('Login: Session regeneration failed:', err);
                        return res.status(500).send('Error processing login (session regen).');
                    }
                    console.log(`Login: Session regenerated. New Session ID: ${req.sessionID}`);

                    req.session.authenticated = true;
                    req.session.username = user.name;
                    req.session.email = user.email;
                    req.session.userId = user._id;
                    console.log(`Login: Session data set for ${user.name}. Authenticated: ${req.session.authenticated}`);

                    req.session.save(function(err) {
                        if (err) {
                            console.error('Login: req.session.save() FAILED:', err);
                            return res.status(500).send('Error saving session after login.');
                        }
                        console.log(`Login: req.session.save() SUCCEEDED for Session ID: ${req.sessionID}. Redirecting to /parrots...`);
                        res.redirect('/parrots');
                    });
                });
            } else {
                console.log(`Login attempt: Incorrect password for email ${email}.`);
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }
        } catch (err) {
            console.error("Login: Overall catch block error:", err);
            res.status(500).send('Login failed');
        }
    }
);

// Protected route
app.get('/parrots', isAuthenticated, (req, res) => { /* ... your existing code ... */
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

// Logout route
app.get('/logout', (req, res) => { /* ... your existing code ... */
    const username = req.session.username;
    const sessionID = req.sessionID;
    req.session.destroy(err => { 
        if (err) {
            console.error(`Logout Error for Session ID ${sessionID}:`, err);
        } else {
            console.log(`User ${username} (Session ID: ${sessionID}) logged out and session destroyed.`);
        }
        res.clearCookie('connect.sid', { path: '/' }); 
        res.redirect('/');
    });
});

// Fallback 404
app.use((req, res, next) => { /* ... your existing code ... */
    res.status(404).send('Page not found - 404');
});

// Generic Error handling middleware
app.use((err, req, res, next) => { /* ... your existing code ... */
    console.error("Unhandled Error:", err.stack);
    res.status(500).send('Something broke!');
});


// --- Ensure database connection before starting server ---
// This is a simplified approach. Ideally, your databaseConnection.js exports a connect function.
// For now, we'll assume it connects synchronously or userCollection is available.
if (!userCollection) {
    console.error("FATAL: userCollection is not available at the time of starting the server. Check databaseConnection.js");
    // In a real app, you'd await a connection function here before app.listen
    // Forcing an exit because routes will fail.
    process.exit(1);
}

app.listen(port, () => {
    console.log(`Node application listening on port ${port}`);
    console.log(`NODE_ENV: ${process.env.NODE_ENV}`); // Log NODE_ENV
    console.log(`User DB configured for: ${mongodb_database} on host ${mongodb_host}`);
    const checkSessionUrl = sessionMongoUrl.replace(mongodb_password, '****');
    console.log(`Session store configured for URL: ${checkSessionUrl}`);
});