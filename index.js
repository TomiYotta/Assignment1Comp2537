
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

// Validate environment variables (Essential for deployment)
if (!process.env.NODE_SESSION_SECRET || !process.env.MONGODB_SESSION_SECRET || !process.env.MONGODB_USER || !process.env.MONGODB_PASSWORD || !process.env.MONGODB_HOST) {
    console.error('FATAL ERROR: Session secrets or MongoDB connection details missing in environment variables.');
    process.exit(1);
}

/* Database Configuration */
// IMPORTANT: Also add "?retryWrites=true&w=majority" to the connection string inside databaseConnection.js
const { database } = require('./databaseConnection');
const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');

// Session configuration
const sessionStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/sessions?retryWrites=true&w=majority`,
    crypto: {
        secret: process.env.MONGODB_SESSION_SECRET
    },
    ttl: 60 * 60 
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
        secure: process.env.NODE_ENV === 'production' 
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
    if (req.session.authenticated) {
        return next();
    }
    res.redirect('/login');
}

// Root route - Adjust links based on login status
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
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(8).required() 
    })),
    async (req, res) => {
        const { name, email, password } = req.body;
        try {
            // Check if user exists
            const existingUser = await userCollection.findOne({ email: email });
            if (existingUser) {
                return res.status(409).send('Email already in use. <a href="/login">Login</a>');
            }
            // Hash password and create user
            const hashedPassword = await bcrypt.hash(password, 12);
            const result = await userCollection.insertOne({
                name: name,
                email: email,
                password: hashedPassword
            });
            // Log user in
            req.session.authenticated = true;
            req.session.username = name;
            req.session.userId = result.insertedId; 
            res.redirect('/parrots');
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
        email: Joi.string().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        const { email, password } = req.body;
        try {
            const user = await userCollection.findOne({ email: email });
            // Verify user exists and password is correct
            if (!user || !(await bcrypt.compare(password, user.password))) {
                return res.status(401).send('Invalid email or password. <a href="/login">Try again</a>');
            }
            // Log user in
            req.session.authenticated = true;
            req.session.username = user.name;
            req.session.userId = user._id; 
            res.redirect('/parrots');
        } catch (err) {
            console.error("Login Error:", err);
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
    req.session.destroy(err => {
        if (err) {
            console.error("Logout Error:", err);
            // Even if error, try to redirect
            return res.redirect('/');
        }
        res.redirect('/'); 
    });
});

// Error handling middleware (Generic 500)
app.use((err, req, res, next) => {
    console.error(err.stack); 
    res.status(500).send('Something broke!');
});

// 404 handler (Catch-all for undefined routes)
app.use((req, res) => {
    res.status(404).send('Page not found - 404');
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Connecting to MongoDB: ${process.env.MONGODB_HOST}`);
});