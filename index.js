// require("./utils.js"); // Uncomment if you have a utils.js file
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require("joi");
const path = require('path');

const port = process.env.PORT || 3000;
const app = express();




// Validate essential environment variables on startup
if (!process.env.NODE_SESSION_SECRET || !process.env.MONGODB_SESSION_SECRET || !process.env.MONGODB_USER || !process.env.MONGODB_PASSWORD || !process.env.MONGODB_HOST || !process.env.MONGODB_DATABASE) {
    console.error('FATAL ERROR: Session secrets or MongoDB connection details missing in environment variables. Check Render Environment Variables.');
    process.exit(1);
}

/* Database Configuration (Users) */
// Ensure databaseConnection.js uses MONGODB_DATABASE and "?retryWrites=true&w=majority"
const { database } = require('./databaseConnection');
const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');

// Session Configuration (Using a 'sessions' database)
const sessionMongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/sessions?retryWrites=true&w=majority`;
console.log(`Session Store URL: ${sessionMongoUrl.replace(process.env.MONGODB_PASSWORD, '********')}`); 

const sessionStore = MongoStore.create({
    mongoUrl: sessionMongoUrl,
    crypto: {
        secret: process.env.MONGODB_SESSION_SECRET
    },
    ttl: 60 * 60 // 1 hour in seconds
});

sessionStore.on('error', function(error) { 
    console.error('Session Store Error:', error);
});


app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: sessionStore,
    saveUninitialized: false, 
    resave: false,            
    cookie: {
        maxAge: 60 * 60 * 1000, 
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
            console.error("Validation Error:", error.details);
            return res.status(400).send(`Invalid input: ${error.details[0].message}. <a href="javascript:history.back()">Go Back</a>`);
        }
        next();
    };
}

// Authentication Check Middleware
function isAuthenticated(req, res, next) {
    console.log(`isAuthenticated Check for path: ${req.path}`);
    console.log(`  Session ID: ${req.sessionID}`); 
    console.log(`  Session Authenticated: ${req.session.authenticated}`); 


    if (req.session.authenticated) {
        console.log(`  Authentication Check Passed.`);
        return next(); // User is authenticated, proceed
    } else {
        console.log(`  Authentication Check Failed. Redirecting to /login.`);
        res.redirect('/login'); 
    }
}

// Root route
app.get('/', (req, res) => {
    let navLinks;
    if (req.session.authenticated) {
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
            <input name="name" placeholder="Name" required><br>
            <input name="email" type="email" placeholder="Email" required><br>
            <input name="password" type="password" placeholder="Password (min 8 chars)" required><br>
            <button type="submit">Submit</button>
        </form>
        <a href="/login">Already have an account? Login</a>
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
            const existingUser = await userCollection.findOne({ email: email });
            if (existingUser) {
                return res.status(409).send('Email already in use. <a href="/login">Login</a>');
            }
            const hashedPassword = await bcrypt.hash(password, 12);
            const result = await userCollection.insertOne({
                name: name,
                email: email,
                password: hashedPassword,
                createdAt: new Date() // Good practice to add timestamp
            });

            // Regenerate session ID upon login/signup for security
            req.session.regenerate(err => {
                if (err) {
                    console.error("Session regeneration error on signup:", err);
                     return res.status(500).send('Error setting up user session.');
                }

                // Set session data AFTER regenerating
                req.session.authenticated = true;
                req.session.username = name;
                req.session.userId = result.insertedId;
                console.log(`Session regenerated and set for ${name} after signup. New Session ID: ${req.sessionID}`);

                req.session.save(err => {
                    if (err) {
                        console.error("Session save error after regeneration on signup:", err);
                        return res.status(500).send('Error creating user session.');
                    }
                    console.log("Session saved successfully after regeneration, redirecting to /parrots");
                    res.redirect('/parrots');
                });
            });
        } catch (err) {
            console.error("Signup Error:", err);
            res.status(500).send('Error creating user');
        }
    }
);

// Login form
app.get('/login', (req, res) => {
    res.send(`
        <h1>Login</h1>
        <form action="/login" method="post">
            <input name="email" type="email" placeholder="Email" required><br>
            <input name="password" type="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
        <a href="/signup">Don't have an account? Sign Up</a>
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
            const user = await userCollection.findOne({ email: email });
            if (!user || !(await bcrypt.compare(password, user.password))) {
                console.warn(`Login attempt failed for email: ${email}`);
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }

            // Regenerate session ID upon login for security
             req.session.regenerate(err => {
                if (err) {
                    console.error("Session regeneration error on login:", err);
                    return res.status(500).send('Error setting up user session.');
                }
                req.session.authenticated = true;
                req.session.username = user.name;
                req.session.userId = user._id; 
                console.log(`Session regenerated and set for ${user.name} after login. New Session ID: ${req.sessionID}`);
                 req.session.save(err => {
                    if (err) {
                        console.error("Session save error after regeneration on login:", err);
                         return res.status(500).send('Login session could not be saved.');
                     }
                     console.log("Session saved successfully after regeneration, redirecting to /parrots");
                    res.redirect('/parrots');
                });
            });
        } catch (err) {
            console.error("Login Error:", err);
            res.status(500).send('Login failed due to server error.');
        }
    }
);

// Protected route
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

// Logout route
app.get('/logout', (req, res) => {
    const username = req.session.username;
    const sessionID = req.sessionID;
    req.session.destroy(err => {
        if (err) {
            console.error(`Logout Error for Session ID ${sessionID}:`, err);
        } else {
            console.log(`User ${username} (Session ID: ${sessionID}) logged out and session destroyed.`);
        }
        // Clear the cookie on the client side
        res.clearCookie('connect.sid', { path: '/' }); 
        res.redirect('/');
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error("Unhandled Error caught by middleware:", err.stack);
    res.status(500).send('Something broke!');
});

// 404 handler (place AFTER all other routes)
app.use((req, res) => {
    console.log(`404 Not Found: ${req.method} ${req.originalUrl}`);
    res.status(404).send('Page not found - 404');
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`NODE_ENV: ${process.env.NODE_ENV}`);
    console.log(`Attempting to connect to user DB on host: ${process.env.MONGODB_HOST}`);
});