require("./utils.js"); 
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require("joi");
const path = require('path');

const { connectToDatabase } = require('./databaseConnection'); 

const port = process.env.PORT || 3000;
const app = express();
app.set('trust proxy', 1); 

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000; 

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

// Input Validation Middleware
function validateInput(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            return res.status(400).send(`Invalid input: ${error.details[0].message}. <a href="javascript:history.back()">Go Back</a>`);
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
    validateInput(Joi.object({
        name: Joi.string().trim().required(),
        email: Joi.string().trim().email().required(),
        password: Joi.string().min(8).required()
    })),
    async (req, res) => {
        const { name, email, password } = req.body;
        try {
            if (!userCollection) {
                return res.status(500).send('Server configuration error (DB not ready).');
            }
            const existingUser = await userCollection.findOne({ email: email });
            if (existingUser) {
                return res.status(409).send('Email already in use. <a href="/login">Login</a>');
            }
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const result = await userCollection.insertOne({
                name: name, email: email, password: hashedPassword, createdAt: new Date()
            });

            req.session.regenerate(function(err) {
                if (err) {
                    return res.status(500).send('Error processing signup (session regen).');
                }
                req.session.authenticated = true;
                req.session.username = name;
                req.session.email = email;
                req.session.userId = result.insertedId;

                req.session.save(function(err) {
                    if (err) {
                        return res.status(500).send('Error saving session after signup.');
                    }
                    res.redirect('/parrots');
                });
            });
        } catch (err) {
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
    validateInput(Joi.object({
        email: Joi.string().trim().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        const { email, password } = req.body;
        try {
            if (!userCollection) {
                return res.status(500).send('Server configuration error (DB not ready).');
            }
            const user = await userCollection.findOne({ email: email });
            if (!user) {
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }

            if (await bcrypt.compare(password, user.password)) {
                req.session.regenerate(function(err) {
                    if (err) {
                        return res.status(500).send('Error processing login (session regen).');
                    }
                    req.session.authenticated = true;
                    req.session.username = user.name;
                    req.session.email = user.email;
                    req.session.userId = user._id;

                    req.session.save(function(err) {
                        if (err) {
                            return res.status(500).send('Error saving session after login.');
                        }
                        res.redirect('/parrots');
                    });
                });
            } else {
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }
        } catch (err) {
            res.status(500).send('Login failed');
        }
    }
);

// Protected route
app.get('/parrots', isAuthenticated, (req, res) => {
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
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                console.error('SERVER: Logout Error:', err);
            }
            res.clearCookie('connect.sid', { path: '/' });
            res.redirect('/');
        });
    } else {
        res.clearCookie('connect.sid', { path: '/' });
        res.redirect('/');
    }
});

// Fallback 404 (should be after all other specific routes)
app.use((req, res, next) => {
    res.status(404).send('Page not found - 404');
});

// Generic Error handling middleware (should be last app.use())
app.use((err, req, res, next) => {
    console.error("SERVER: Unhandled Error:", err.stack);
    res.status(500).send('Something broke on the server!');
});

// --- Initialize Database and Start Server ---
async function startServer() {
    try {
        dbInstance = await connectToDatabase();
        if (!dbInstance) {
            console.error("SERVER_START: connectToDatabase() did not return a valid DB instance. Exiting.");
            process.exit(1);
        }
        userCollection = dbInstance.collection('users');

        app.listen(port, () => {
            console.log(`Server listening on port ${port}`);
        });

    } catch (error) {
        console.error("SERVER_START: Failed to initialize database or start the server:", error);
        process.exit(1);
    }
}

startServer();