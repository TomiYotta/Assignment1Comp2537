require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require("joi");
const path = require('path');

const port = process.env.PORT || 3000;
const app = express();

// Validate environment variables
if (!process.env.NODE_SESSION_SECRET || !process.env.MONGODB_SESSION_SECRET) {
    console.error('FATAL ERROR: Session secrets not configured in .env file');
    process.exit(1);
}

/* Database Configuration */
const { database } = require('./databaseConnection');
const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');

// Session configuration
const sessionStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/sessions`,
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

function validateInput(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            console.log(error.details);
            return res.status(400).send(error.details[0].message);
        }
        next();
    };
}

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        return res.send(`
            <a href="/signup">Sign Up</a>
            <a href="/login">Login</a>
        `);
    }
    res.send(`
        <a href="/signup">Sign Up</a>
        <a href="/login">Login</a>
    `);
});

app.get('/signup', (req, res) => {
    res.send(`
        <h1>Sign Up</h1>
        <form action="/signup" method="post">
            <input name="name" placeholder="Name" required>
            <input name="email" type="email" placeholder="Email" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Submit</button>
        </form>
    `);
});

app.post('/signup', 
    validateInput(Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(8).required()
    })),
    async (req, res) => {
        try {
            const hashedPassword = await bcrypt.hash(req.body.password, 12);
            await userCollection.insertOne({
                name: req.body.name,
                email: req.body.email,
                password: hashedPassword
            });
            
            req.session.authenticated = true;
            req.session.username = req.body.name;
            res.redirect('/parrots');
        } catch (err) {
            console.error(err);
            res.status(500).send('Error creating user');
        }
    }
);

app.get('/login', (req, res) => {
    res.send(`
        <h1>Login</h1>
        <form action="/login" method="post">
            <input name="email" type="email" placeholder="Email" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    `);
});

app.post('/login', 
    validateInput(Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    })),
    async (req, res) => {
        try {
            const user = await userCollection.findOne({ email: req.body.email });
            if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
                return res.status(401).send('Invalid email or password');
            }
            
            req.session.authenticated = true;
            req.session.username = user.name;
            res.redirect('/parrots');
        } catch (err) {
            console.error(err);
            res.status(500).send('Login failed');
        }
    }
);

app.get('/parrots', (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }
    
    const images = ['parrot.jpeg', 'parrot2.jpeg', 'parrot3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
    
    res.send(`
        <h1>Welcome, ${req.session.username}!</h1>
        <img src="/images/${randomImage}" alt="Random parrot" style="max-width: 500px;">
        <a href="/logout">Logout</a>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error(err);
        res.redirect('/');
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// 404 handler
app.use((req, res) => {
    res.status(404).send('Page not found - 404');
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Connected to MongoDB: ${process.env.MONGODB_HOST}`);
});

