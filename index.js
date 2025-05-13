// server.js (with trust proxy optimally placed and continued logging)
require('dotenv').config();

const express = require('express');
// Place app.set('trust proxy', 1) immediately after app is created
const app = express();
app.set('trust proxy', 1); // IMPORTANT: Tells Express to trust X-Forwarded-* headers from Render's proxy

const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require("joi");
const path = require('path');
const { ObjectId } = require('mongodb');

const { connectToDatabase } = require('./databaseConnection');

const port = process.env.PORT || 3000;

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database_for_users = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

console.log("SERVER START: ---- Environment Variables Check ----");
console.log("MONGODB_HOST:", mongodb_host ? "SET" : "MISSING!");
console.log("MONGODB_USER:", mongodb_user ? "SET" : "MISSING!");
// console.log("MONGODB_PASSWORD:", mongodb_password ? "SET" : "MISSING!"); // Avoid logging password directly
console.log("MONGODB_DATABASE:", mongodb_database_for_users ? "SET" : "MISSING!");
console.log("MONGODB_SESSION_SECRET:", mongodb_session_secret ? "SET" : "MISSING!");
console.log("NODE_SESSION_SECRET:", node_session_secret ? "SET" : "MISSING!");
console.log("NODE_ENV:", process.env.NODE_ENV);
console.log("-------------------------------------------------");

if (!node_session_secret || !mongodb_session_secret || !mongodb_user || !mongodb_password || !mongodb_host || !mongodb_database_for_users) {
    console.error('FATAL ERROR SERVER: Essential environment variables missing. Check .env and Render Environment Variables.');
    process.exit(1);
}

let userCollection;
let dbInstance;

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files middleware (for CSS, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));
// Body parsing middleware
app.use(express.urlencoded({ extended: false }));


// Session store setup
const sessionMongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database_for_users}?retryWrites=true&w=majority`;
console.log("SESSION_STORE: Attempting to connect to MongoDB for sessions at host:", mongodb_host);

const mongoStore = MongoStore.create({
    mongoUrl: sessionMongoUrl,
    collectionName: 'sessions',
    crypto: {
        secret: mongodb_session_secret
    },
    touchAfter: 24 * 3600,
});

mongoStore.on('create', (sessionId) => console.log('SESSION_STORE: Session created with ID:', sessionId));
mongoStore.on('touch', (sessionId) => console.log('SESSION_STORE: Session touched with ID:', sessionId));
mongoStore.on('update', (sessionId) => console.log('SESSION_STORE: Session updated with ID:', sessionId));
mongoStore.on('destroy', (sessionId) => console.log('SESSION_STORE: Session destroyed with ID:', sessionId));
mongoStore.on('error', (error) => console.error('SERVER: FATAL SESSION STORE ERROR (connect-mongo):', error));
mongoStore.on('connected', () => console.log('SESSION_STORE: Successfully connected to MongoDB for sessions.'));
mongoStore.on('disconnected', () => console.error('SESSION_STORE: Disconnected from MongoDB for sessions. This is a problem!'));

// Session middleware
app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: expireTime,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // True if NODE_ENV is 'production'
        sameSite: 'lax'
    }
}));
console.log("SESSION_MIDDLEWARE: Session middleware initialized. Secure cookie active:", process.env.NODE_ENV === 'production');

// Middleware to log session state and make session data available to templates
app.use((req, res, next) => {
    console.log(`REQUEST: ${req.method} ${req.url} - Session ID: ${req.sessionID}`);
    if (req.session) {
        console.log(`REQUEST_SESSION_DATA: Authenticated: ${req.session.authenticated}, User: ${req.session.username}, Type: ${req.session.user_type}`);
    } else {
        console.log("REQUEST_SESSION_DATA: No session object found on req.");
    }
    res.locals.authenticated = req.session ? req.session.authenticated : false;
    res.locals.username = req.session ? req.session.username : null;
    res.locals.user_type = req.session ? req.session.user_type : null;
    res.locals.userId = req.session ? req.session.userId : null; // Make userId available if needed
    next();
});

// --- Helper Middlewares ---
function validateInput(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            console.log("VALIDATION_ERROR:", error.details[0].message);
            return res.status(400).render('error', {
                message: `Invalid input: ${error.details[0].message}.`,
                title: "Input Error"
            });
        }
        next();
    };
}

function isAuthenticated(req, res, next) {
    console.log(`AUTH_CHECK for ${req.originalUrl}: Session Authenticated: ${req.session ? req.session.authenticated : 'No session (or undefined)'}`);
    if (req.session && req.session.authenticated) {
        console.log(`AUTH_CHECK for ${req.originalUrl}: Access GRANTED for user ${req.session.username}`);
        return next();
    }
    console.log(`AUTH_CHECK for ${req.originalUrl}: Access DENIED. Redirecting to /login.`);
    res.redirect('/login');
}

function isAdmin(req, res, next) {
    console.log(`ADMIN_CHECK for ${req.originalUrl}: Session Authenticated: ${req.session ? req.session.authenticated : 'No session'}, User Type: ${req.session ? req.session.user_type : 'No session'}`);
    if (req.session && req.session.authenticated && req.session.user_type === 'admin') {
        console.log(`ADMIN_CHECK for ${req.originalUrl}: Admin access GRANTED for user ${req.session.username}`);
        return next();
    }
    if (req.session && req.session.authenticated) {
        console.log(`ADMIN_CHECK for ${req.originalUrl}: Access DENIED (Not Admin). User: ${req.session.username}, Type: ${req.session.user_type}. Sending 403.`);
        return res.status(403).render('error', {
            message: "Access Denied. You do not have administrator privileges.",
            title: "Forbidden",
            statusCode: 403
        });
    }
    console.log(`ADMIN_CHECK for ${req.originalUrl}: Access DENIED (Not Logged In). Redirecting to /login.`);
    res.redirect('/login');
}

// --- Routes ---
app.get('/', (req, res) => {
    console.log("ROUTE: GET /");
    res.render('index', { title: "Home" });
});

app.get('/signup', (req, res) => {
    console.log("ROUTE: GET /signup");
    res.render('signup', { title: "Sign Up" });
});

app.post('/signup',
    validateInput(Joi.object({
        name: Joi.string().trim().required(),
        email: Joi.string().trim().email().required(),
        password: Joi.string().min(8).required()
    })),
    async (req, res) => {
        console.log("ROUTE: POST /signup - Attempting to sign up user:", req.body.email);
        const { name, email, password } = req.body;
        try {
            if (!userCollection) {
                console.error("SIGNUP_ERROR: userCollection not initialized.");
                return res.status(500).render('error', { message: 'Server configuration error (DB not ready).', title: "Server Error" });
            }
            const existingUser = await userCollection.findOne({ email: email });
            if (existingUser) {
                console.log("SIGNUP_ERROR: Email already in use:", email);
                return res.status(409).render('error', {
                    message: 'Email already in use.',
                    title: "Signup Error",
                    linkText: "Login",
                    linkHref: "/login"
                });
            }
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const result = await userCollection.insertOne({
                name: name, email: email, password: hashedPassword, user_type: 'user', createdAt: new Date()
            });
            console.log("SIGNUP_SUCCESS: User created with ID:", result.insertedId);

            req.session.regenerate(function(err) {
                if (err) {
                    console.error("SIGNUP_ERROR: Session regeneration failed:", err);
                    return res.status(500).render('error', { message: 'Error processing signup (session regen).', title: "Server Error" });
                }
                // The new session ID will be available *after* regenerate completes and req.session.save is called.
                // Log the current (potentially old or new if already set) session ID for context.
                console.log("SIGNUP_SESSION: Session regenerated (ID before save might be new one, or old one if regen is async regarding ID exposure). Current req.sessionID:", req.sessionID);
                req.session.authenticated = true;
                req.session.username = name;
                req.session.email = email;
                req.session.userId = result.insertedId.toString(); // Store as string for consistency
                req.session.user_type = 'user';
                console.log("SIGNUP_SESSION: Session data set. Authenticated:", req.session.authenticated, "User:", req.session.username);

                req.session.save(function(err) {
                    if (err) {
                        console.error("SIGNUP_ERROR: Session save failed:", err);
                        return res.status(500).render('error', { message: 'Error saving session after signup.', title: "Server Error" });
                    }
                    console.log("SIGNUP_SESSION: Session saved successfully! Redirecting to /parrots. Session ID after save:", req.sessionID);
                    res.redirect('/parrots');
                });
            });
        } catch (err) {
            console.error("SIGNUP_ERROR: Catch block error:", err);
            res.status(500).render('error', { message: 'Error creating user.', title: "Server Error" });
        }
    }
);

app.get('/login', (req, res) => {
    console.log("ROUTE: GET /login");
    res.render('login', { title: "Login" });
});

app.post('/login',
    validateInput(Joi.object({
        email: Joi.string().trim().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        console.log("ROUTE: POST /login - Attempting login for user:", req.body.email);
        const { email, password } = req.body;
        try {
            if (!userCollection) {
                console.error("LOGIN_ERROR: userCollection not initialized.");
                return res.status(500).render('error', { message: 'Server configuration error (DB not ready).', title: "Server Error" });
            }
            const user = await userCollection.findOne({ email: email });
            if (!user) {
                console.log("LOGIN_ERROR: User not found:", email);
                return res.status(401).render('error', {
                    message: 'Invalid email or password.',
                    title: "Login Failed",
                    linkText: "Try again",
                    linkHref: "/login"
                });
            }
            console.log("LOGIN_INFO: User found:", user.name, "Type:", user.user_type);

            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                console.log("LOGIN_SUCCESS: Password match for user:", user.email);
                req.session.regenerate(function(err) {
                    if (err) {
                        console.error("LOGIN_ERROR: Session regeneration failed:", err);
                        return res.status(500).render('error', { message: 'Error processing login (session regen).', title: "Server Error" });
                    }
                    console.log("LOGIN_SESSION: Session regenerated. Current req.sessionID:", req.sessionID);
                    req.session.authenticated = true;
                    req.session.username = user.name;
                    req.session.email = user.email;
                    req.session.userId = user._id.toString(); // Store as string
                    req.session.user_type = user.user_type;
                    console.log("LOGIN_SESSION: Session data set. Authenticated:", req.session.authenticated, "User:", req.session.username, "Type:", req.session.user_type);

                    req.session.save(function(err) {
                        if (err) {
                            console.error("LOGIN_ERROR: Session save failed:", err);
                            return res.status(500).render('error', { message: 'Error saving session after login.', title: "Server Error" });
                        }
                        console.log("LOGIN_SESSION: Session saved successfully! Redirecting to /parrots. Session ID after save:", req.sessionID);
                        res.redirect('/parrots');
                    });
                });
            } else {
                console.log("LOGIN_ERROR: Password mismatch for user:", user.email);
                return res.status(401).render('error', {
                    message: 'Invalid email or password.',
                    title: "Login Failed",
                    linkText: "Try again",
                    linkHref: "/login"
                });
            }
        } catch (err) {
            console.error("LOGIN_ERROR: Catch block error:", err);
            res.status(500).render('error', { message: 'Login failed due to a server error.', title: "Server Error" });
        }
    }
);

app.get('/parrots', isAuthenticated, (req, res) => {
    console.log("ROUTE: GET /parrots - Accessed by user:", req.session.username);
    const images = ['parrot.jpeg', 'parrot2.jpeg', 'parrot3.jpg']; // Ensure these are in public/images
    res.render('parrots', {
        title: "Parrots Sanctuary",
        images: images // This variable is used in parrots.ejs
    });
});

app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    console.log("ROUTE: GET /admin - Accessed by admin user:", req.session.username);
    try {
        if (!userCollection) {
            console.error("ADMIN_ERROR: userCollection not initialized.");
            return res.status(500).render('error', { message: 'Server configuration error (DB not ready).', title: "Server Error" });
        }
        const users = await userCollection.find({}, { projection: { password: 0 } }).toArray();
        res.render('admin', {
            title: "Admin Panel",
            users: users
        });
    } catch (err) {
        console.error("ADMIN_ERROR: Error fetching users:", err);
        res.status(500).render('error', { message: 'Failed to load admin data.', title: "Server Error" });
    }
});

app.post('/admin/promote/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userId = req.params.userId;
    console.log(`ROUTE: POST /admin/promote/${userId} - Action by admin:`, req.session.username);
    try {
        if (!ObjectId.isValid(userId)) {
             console.error("ADMIN_PROMOTE_ERROR: Invalid user ID format:", userId);
            return res.status(400).render('error', { message: 'Invalid user ID format.', title: "Admin Action Error" });
        }
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'admin' } });
        console.log("ADMIN_PROMOTE_SUCCESS: User promoted:", userId);
        res.redirect('/admin');
    } catch (err) {
        console.error("ADMIN_PROMOTE_ERROR: Catch block error:", err);
        res.status(500).render('error', { message: 'Failed to promote user.', title: "Server Error" });
    }
});

app.post('/admin/demote/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userId = req.params.userId;
     console.log(`ROUTE: POST /admin/demote/${userId} - Action by admin:`, req.session.username);
    try {
        if (!ObjectId.isValid(userId)) {
            console.error("ADMIN_DEMOTE_ERROR: Invalid user ID format:", userId);
            return res.status(400).render('error', { message: 'Invalid user ID format.', title: "Admin Action Error" });
        }
        // Basic check to prevent self-demotion if they are the only admin.
        // More robust logic might be needed for production.
        if (req.session.userId === userId) {
            const adminCount = await userCollection.countDocuments({ user_type: 'admin' });
            if (adminCount <= 1) {
                console.log("ADMIN_DEMOTE_ERROR: Cannot demote the last admin (self).");
                return res.status(403).render('error', { message: 'Cannot demote the last admin.', title: "Admin Action Error" });
            }
        }
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'user' } });
        console.log("ADMIN_DEMOTE_SUCCESS: User demoted:", userId);
        res.redirect('/admin');
    } catch (err) {
        console.error("ADMIN_DEMOTE_ERROR: Catch block error:", err);
        res.status(500).render('error', { message: 'Failed to demote user.', title: "Server Error" });
    }
});

app.get('/logout', (req, res) => {
    console.log("ROUTE: GET /logout - User logging out:", req.session ? req.session.username : "Unknown (no session/already destroyed)");
    if (req.session) {
        const username = req.session.username;
        req.session.destroy(err => {
            if (err) {
                console.error('LOGOUT_ERROR: Error destroying session:', err);
            } else {
                console.log("LOGOUT_SUCCESS: Session destroyed for user:", username);
            }
            // The cookie name 'connect.sid' is the default for express-session.
            // If you've configured a different name in session options, use that here.
            res.clearCookie('connect.sid', { path: '/' });
            console.log("LOGOUT_INFO: Cleared session cookie ('connect.sid'). Redirecting to /");
            res.redirect('/');
        });
    } else {
        console.log("LOGOUT_INFO: No session found (already destroyed or never existed). Clearing cookie and redirecting.");
        res.clearCookie('connect.sid', { path: '/' });
        res.redirect('/');
    }
});

// 404 Handler (must be after all other routes)
app.use((req, res, next) => {
    console.log(`404_HANDLER: Page not found for ${req.method} ${req.originalUrl}`);
    res.status(404).render('404', { title: "Page Not Found" });
});

// Generic Error Handler (must be the last app.use())
app.use((err, req, res, next) => {
    console.error("UNHANDLED_ERROR_MIDDLEWARE: Error occurred for request:", req.method, req.url);
    console.error(err.stack); // Log the full error stack
    res.status(err.status || 500).render('error', {
        message: err.message || 'Something broke on the server!',
        title: "Server Error",
        statusCode: err.status || 500
    });
});

// --- Initialize Database and Start Server ---
async function startServer() {
    console.log("SERVER_START: Attempting to connect to database...");
    try {
        dbInstance = await connectToDatabase();
        if (!dbInstance) {
            console.error("SERVER_START_FATAL: connectToDatabase() did not return a valid DB instance. Exiting.");
            process.exit(1);
        }
        console.log("SERVER_START: Database connection successful.");
        userCollection = dbInstance.collection('users');
        console.log("SERVER_START: userCollection initialized. Using collection 'users'.");

        app.listen(port, () => {
            console.log(`SERVER_START: Server listening on port ${port}. NODE_ENV: ${process.env.NODE_ENV}`);
        });

    } catch (error) {
        console.error("SERVER_START_FATAL: Failed to initialize database or start the server:", error);
        process.exit(1);
    }
}

startServer();