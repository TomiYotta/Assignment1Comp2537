require('dotenv').config(); // Ensure this is at the very top

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require("joi");
const path = require('path');
const { ObjectId } = require('mongodb'); // For working with _id

const { connectToDatabase } = require('./databaseConnection'); // Assuming this file exists

const port = process.env.PORT || 3000;
const app = express();
app.set('trust proxy', 1);

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database_for_users = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

if (!node_session_secret || !mongodb_session_secret || !mongodb_user || !mongodb_password || !mongodb_host || !mongodb_database_for_users) {
    console.error('FATAL ERROR SERVER: Essential environment variables missing. Check .env and Render Environment Variables.');
    process.exit(1);
}

let userCollection;
let dbInstance;

// Set EJS as the templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Specify the views directory

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

/* --- Session Configuration --- */
const sessionMongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database_for_users}?retryWrites=true&w=majority`;

const mongoStore = MongoStore.create({
    mongoUrl: sessionMongoUrl,
    collectionName: 'sessions',
    crypto: {
        secret: mongodb_session_secret
    },
    touchAfter: 24 * 3600,
});

mongoStore.on('error', (error) => console.error('SERVER: FATAL SESSION STORE ERROR (connect-mongo):', error));

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: expireTime,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));

// Middleware to make session data available to all templates
app.use((req, res, next) => {
    res.locals.authenticated = req.session.authenticated;
    res.locals.username = req.session.username;
    res.locals.user_type = req.session.user_type;
    next();
});


// Input Validation Middleware
function validateInput(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            return res.status(400).render('error', {
                message: `Invalid input: ${error.details[0].message}.`,
                title: "Input Error"
            });
        }
        next();
    };
}

// Authentication Check Middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.authenticated) {
        return next();
    }
    res.redirect('/login');
}

// Admin Check Middleware
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


// Root route
app.get('/', (req, res) => {
    res.render('index', { title: "Home" });
});

// Signup form
app.get('/signup', (req, res) => {
    res.render('signup', { title: "Sign Up" });
});

// Signup logic
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
                return res.status(500).render('error', { message: 'Server configuration error (DB not ready).', title: "Server Error" });
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
                name: name,
                email: email,
                password: hashedPassword,
                user_type: 'user', // Default to 'user'
                createdAt: new Date()
            });

            req.session.regenerate(function(err) {
                if (err) {
                    console.error("SERVER: Session regeneration error on signup:", err);
                    return res.status(500).render('error', { message: 'Error processing signup (session regen).', title: "Server Error" });
                }
                req.session.authenticated = true;
                req.session.username = name;
                req.session.email = email;
                req.session.userId = result.insertedId;
                req.session.user_type = 'user'; // Set user_type in session

                req.session.save(function(err) {
                    if (err) {
                        console.error("SERVER: Session save error on signup:", err);
                        return res.status(500).render('error', { message: 'Error saving session after signup.', title: "Server Error" });
                    }
                    res.redirect('/parrots');
                });
            });
        } catch (err) {
            console.error("SERVER: Error creating user:", err);
            res.status(500).render('error', { message: 'Error creating user.', title: "Server Error" });
        }
    }
);

// Login form
app.get('/login', (req, res) => {
    res.render('login', { title: "Login" });
});

// Login logic
app.post('/login',
    validateInput(Joi.object({
        email: Joi.string().trim().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        const { email, password } = req.body;
        try {
            if (!userCollection) {
                return res.status(500).render('error', { message: 'Server configuration error (DB not ready).', title: "Server Error" });
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

            if (await bcrypt.compare(password, user.password)) {
                req.session.regenerate(function(err) {
                    if (err) {
                        console.error("SERVER: Session regeneration error on login:", err);
                        return res.status(500).render('error', { message: 'Error processing login (session regen).', title: "Server Error" });
                    }
                    req.session.authenticated = true;
                    req.session.username = user.name;
                    req.session.email = user.email;
                    req.session.userId = user._id;
                    req.session.user_type = user.user_type; // Set user_type in session

                    req.session.save(function(err) {
                        if (err) {
                            console.error("SERVER: Session save error on login:", err);
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
            console.error("SERVER: Login failed:", err);
            res.status(500).render('error', { message: 'Login failed due to a server error.', title: "Server Error" });
        }
    }
);

// Parrots page (replaces members page)
app.get('/parrots', isAuthenticated, (req, res) => {
    const images = ['parrot.jpeg', 'parrot2.jpeg', 'parrot3.jpg']; // Ensure these exist in public/images
    res.render('parrots', {
        title: "Parrots Sanctuary",
        images: images
    });
});

// Admin page
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    try {
        if (!userCollection) {
            return res.status(500).render('error', { message: 'Server configuration error (DB not ready).', title: "Server Error" });
        }
        const users = await userCollection.find({}, { projection: { password: 0 } }).toArray(); // Exclude passwords
        res.render('admin', {
            title: "Admin Panel",
            users: users
        });
    } catch (err) {
        console.error("SERVER: Error fetching users for admin page:", err);
        res.status(500).render('error', { message: 'Failed to load admin data.', title: "Server Error" });
    }
});

// Promote user to admin
app.post('/admin/promote/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userId = req.params.userId;
    try {
        if (!ObjectId.isValid(userId)) {
            return res.status(400).render('error', { message: 'Invalid user ID format.', title: "Admin Action Error" });
        }
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'admin' } });
        res.redirect('/admin');
    } catch (err) {
        console.error("SERVER: Error promoting user:", err);
        res.status(500).render('error', { message: 'Failed to promote user.', title: "Server Error" });
    }
});

// Demote user to regular user
app.post('/admin/demote/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userId = req.params.userId;
    try {
        if (!ObjectId.isValid(userId)) {
            return res.status(400).render('error', { message: 'Invalid user ID format.', title: "Admin Action Error" });
        }
        // Prevent admin from demoting themselves if they are the only admin (optional safeguard)
        // const currentUser = await userCollection.findOne({ _id: new ObjectId(req.session.userId) });
        // if (currentUser.user_type === 'admin' && userId === req.session.userId.toString()) {
        //     const adminCount = await userCollection.countDocuments({ user_type: 'admin' });
        //     if (adminCount <= 1) {
        //         return res.status(403).render('error', { message: 'Cannot demote the last admin.', title: "Admin Action Error" });
        //     }
        // }
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'user' } });
        res.redirect('/admin');
    } catch (err) {
        console.error("SERVER: Error demoting user:", err);
        res.status(500).render('error', { message: 'Failed to demote user.', title: "Server Error" });
    }
});


// Logout route
app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                console.error('SERVER: Logout Error:', err);
            }
            res.clearCookie('connect.sid', { path: '/' }); // Ensure cookie is cleared
            res.redirect('/');
        });
    } else {
        res.clearCookie('connect.sid', { path: '/' });
        res.redirect('/');
    }
});

// Fallback 404 (should be after all other specific routes)
app.use((req, res, next) => {
    res.status(404).render('404', { title: "Page Not Found" });
});

// Generic Error handling middleware (should be last app.use())
app.use((err, req, res, next) => {
    console.error("SERVER: Unhandled Error:", err.stack);
    res.status(err.status || 500).render('error', {
        message: err.message || 'Something broke on the server!',
        title: "Server Error",
        statusCode: err.status || 500
    });
});

// --- Initialize Database and Start Server ---
async function startServer() {
    try {
        dbInstance = await connectToDatabase();
        if (!dbInstance) {
            console.error("SERVER_START: connectToDatabase() did not return a valid DB instance. Exiting.");
            process.exit(1);
        }
        userCollection = dbInstance.collection('users'); // Make sure this matches your collection name

        app.listen(port, () => {
            console.log(`Server listening on port ${port}`);
        });

    } catch (error) {
        console.error("SERVER_START: Failed to initialize database or start the server:", error);
        process.exit(1);
    }
}

startServer();