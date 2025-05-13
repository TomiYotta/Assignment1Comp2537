// server.js (or index.js - cleaner version)
require('dotenv').config();

const express = require('express');
const app = express();
app.set('trust proxy', 1); // IMPORTANT: Tells Express to trust X-Forwarded-* headers

const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require("joi");
const path = require('path');
const { ObjectId } = require('mongodb');

const { connectToDatabase } = require('./databaseConnection'); // Ensure this file exists and is correct

const port = process.env.PORT || 3000;

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

// Environment Variables
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database_for_users = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// Essential Environment Variable Check
if (!node_session_secret || !mongodb_session_secret || !mongodb_user || !mongodb_password || !mongodb_host || !mongodb_database_for_users) {
    console.error('FATAL ERROR SERVER: Essential environment variables missing. Check .env and Render Environment Variables.');
    process.exit(1); // Exit if critical variables are not set
}

let userCollection;
let dbInstance;

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files middleware
app.use(express.static(path.join(__dirname, 'public')));
// Body parsing middleware
app.use(express.urlencoded({ extended: false }));

// Session store setup
const sessionMongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database_for_users}?retryWrites=true&w=majority`;

const mongoStore = MongoStore.create({
    mongoUrl: sessionMongoUrl,
    collectionName: 'sessions',
    crypto: {
        secret: mongodb_session_secret
    },
    touchAfter: 24 * 3600, // time period in seconds
});

mongoStore.on('error', (error) => console.error('SERVER: FATAL SESSION STORE ERROR (connect-mongo):', error));
mongoStore.on('connected', () => console.log('SESSION_STORE: Successfully connected to MongoDB for sessions.'));
mongoStore.on('disconnected', () => console.error('SESSION_STORE: Disconnected from MongoDB for sessions.'));


// Session middleware
app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: expireTime,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Enable secure cookies in production
        sameSite: 'lax'
    }
}));

// Middleware to make session data available to all templates
app.use((req, res, next) => {
    res.locals.authenticated = req.session ? req.session.authenticated : false;
    res.locals.username = req.session ? req.session.username : null;
    res.locals.user_type = req.session ? req.session.user_type : null;
    res.locals.userId = req.session ? req.session.userId : null;
    next();
});

// --- Helper Middlewares ---
function validateInput(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            // It's still good to log validation errors on the server for debugging
            console.error("VALIDATION_ERROR:", error.details[0].message, "for request:", req.originalUrl, "Body:", req.body);
            return res.status(400).render('error', {
                message: `Invalid input: ${error.details[0].message}.`,
                title: "Input Error"
            });
        }
        next();
    };
}

function isAuthenticated(req, res, next) {
    if (req.session && req.session.authenticated) {
        return next();
    }
    res.redirect('/login');
}

function isAdmin(req, res, next) {
    if (req.session && req.session.authenticated && req.session.user_type === 'admin') {
        return next();
    }
    if (req.session && req.session.authenticated) { // Logged in but not admin
        return res.status(403).render('error', {
            message: "Access Denied. You do not have administrator privileges.",
            title: "Forbidden",
            statusCode: 403
        });
    }
    res.redirect('/login'); // Not logged in at all
}

// --- Routes ---
app.get('/', (req, res) => {
    res.render('index', { title: "Home" });
});

app.get('/signup', (req, res) => {
    res.render('signup', { title: "Sign Up" });
});

app.post('/signup',
    validateInput(Joi.object({
        name: Joi.string().trim().required(),
        email: Joi.string().trim().email().required(),
        password: Joi.string().min(8).required()
    })),
    async (req, res) => {
        const { name, email, password } = req.body;
        try {
            if (!userCollection) {
                console.error("SIGNUP_ERROR: userCollection not initialized during signup attempt.");
                return res.status(500).render('error', { message: 'Server configuration error.', title: "Server Error" });
            }
            const existingUser = await userCollection.findOne({ email: email });
            if (existingUser) {
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

            req.session.regenerate(function(err) {
                if (err) {
                    console.error("SIGNUP_ERROR: Session regeneration failed:", err);
                    return res.status(500).render('error', { message: 'Error processing signup.', title: "Server Error" });
                }
                req.session.authenticated = true;
                req.session.username = name;
                req.session.email = email;
                req.session.userId = result.insertedId.toString();
                req.session.user_type = 'user';

                req.session.save(function(err) {
                    if (err) {
                        console.error("SIGNUP_ERROR: Session save failed:", err);
                        return res.status(500).render('error', { message: 'Error saving session after signup.', title: "Server Error" });
                    }
                    res.redirect('/parrots');
                });
            });
        } catch (err) {
            console.error("SIGNUP_ERROR: Unhandled exception during signup:", err);
            res.status(500).render('error', { message: 'Error creating user.', title: "Server Error" });
        }
    }
);

app.get('/login', (req, res) => {
    res.render('login', { title: "Login" });
});

app.post('/login',
    validateInput(Joi.object({
        email: Joi.string().trim().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        const { email, password } = req.body;
        try {
            if (!userCollection) {
                 console.error("LOGIN_ERROR: userCollection not initialized during login attempt.");
                return res.status(500).render('error', { message: 'Server configuration error.', title: "Server Error" });
            }
            const user = await userCollection.findOne({ email: email });
            if (!user) {
                return res.status(401).render('error', {
                    message: 'Invalid email or password.',
                    title: "Login Failed",
                    linkText: "Try again",
                    linkHref: "/login"
                });
            }

            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                req.session.regenerate(function(err) {
                    if (err) {
                        console.error("LOGIN_ERROR: Session regeneration failed:", err);
                        return res.status(500).render('error', { message: 'Error processing login.', title: "Server Error" });
                    }
                    req.session.authenticated = true;
                    req.session.username = user.name;
                    req.session.email = user.email;
                    req.session.userId = user._id.toString();
                    req.session.user_type = user.user_type;

                    req.session.save(function(err) {
                        if (err) {
                            console.error("LOGIN_ERROR: Session save failed:", err);
                            return res.status(500).render('error', { message: 'Error saving session after login.', title: "Server Error" });
                        }
                        res.redirect('/parrots');
                    });
                });
            } else {
                return res.status(401).render('error', {
                    message: 'Invalid email or password.',
                    title: "Login Failed",
                    linkText: "Try again",
                    linkHref: "/login"
                });
            }
        } catch (err) {
            console.error("LOGIN_ERROR: Unhandled exception during login:", err);
            res.status(500).render('error', { message: 'Login failed due to a server error.', title: "Server Error" });
        }
    }
);

app.get('/parrots', isAuthenticated, (req, res) => {
    const images = ['parrot.jpeg', 'parrot2.jpeg', 'parrot3.jpg']; // Ensure these exist in public/images
    res.render('parrots', {
        title: "Parrots Sanctuary",
        images: images
    });
});

app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    try {
        if (!userCollection) {
            console.error("ADMIN_ERROR: userCollection not initialized for admin page.");
            return res.status(500).render('error', { message: 'Server configuration error.', title: "Server Error" });
        }
        const users = await userCollection.find({}, { projection: { password: 0 } }).toArray();
        res.render('admin', {
            title: "Admin Panel",
            users: users
        });
    } catch (err) {
        console.error("ADMIN_ERROR: Error fetching users for admin page:", err);
        res.status(500).render('error', { message: 'Failed to load admin data.', title: "Server Error" });
    }
});

app.post('/admin/promote/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userId = req.params.userId;
    try {
        if (!ObjectId.isValid(userId)) {
            return res.status(400).render('error', { message: 'Invalid user ID format.', title: "Admin Action Error" });
        }
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'admin' } });
        res.redirect('/admin');
    } catch (err) {
        console.error("ADMIN_PROMOTE_ERROR: Failed to promote user:", userId, err);
        res.status(500).render('error', { message: 'Failed to promote user.', title: "Server Error" });
    }
});

app.post('/admin/demote/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userId = req.params.userId;
    try {
        if (!ObjectId.isValid(userId)) {
            return res.status(400).render('error', { message: 'Invalid user ID format.', title: "Admin Action Error" });
        }
        if (req.session.userId === userId) { // Prevent self-demotion if they are the only admin
            const adminCount = await userCollection.countDocuments({ user_type: 'admin' });
            if (adminCount <= 1) {
                return res.status(403).render('error', { message: 'Cannot demote the last admin.', title: "Admin Action Error" });
            }
        }
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'user' } });
        res.redirect('/admin');
    } catch (err) {
        console.error("ADMIN_DEMOTE_ERROR: Failed to demote user:", userId, err);
        res.status(500).render('error', { message: 'Failed to demote user.', title: "Server Error" });
    }
});

app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                console.error('LOGOUT_ERROR: Error destroying session:', err);
            }
            res.clearCookie('connect.sid', { path: '/' }); // Default session cookie name
            res.redirect('/');
        });
    } else {
        res.clearCookie('connect.sid', { path: '/' });
        res.redirect('/');
    }
});

// 404 Handler (must be after all other specific routes)
app.use((req, res, next) => {
    res.status(404).render('404', { title: "Page Not Found" });
});

// Generic Error Handler (must be the last app.use() to catch all errors)
app.use((err, req, res, next) => {
    console.error("UNHANDLED_ERROR:", err.stack); // Log the full error stack for debugging
    res.status(err.status || 500).render('error', {
        message: err.message || 'An unexpected error occurred on the server.',
        title: "Server Error",
        statusCode: err.status || 500
    });
});

// --- Initialize Database and Start Server ---
async function startServer() {
    console.log("SERVER_START: Initializing...");
    try {
        dbInstance = await connectToDatabase();
        if (!dbInstance) {
            console.error("SERVER_START_FATAL: connectToDatabase() did not return a valid DB instance. Exiting.");
            process.exit(1);
        }
        console.log("SERVER_START: Database connection successful.");
        userCollection = dbInstance.collection('users');
        console.log("SERVER_START: userCollection initialized.");

        app.listen(port, () => {
            console.log(`SERVER_START: Server listening on port ${port}. NODE_ENV: ${process.env.NODE_ENV}. Secure cookies active: ${process.env.NODE_ENV === 'production'}`);
        });

    } catch (error) {
        console.error("SERVER_START_FATAL: Failed to initialize database or start the server:", error);
        process.exit(1);
    }
}

startServer();