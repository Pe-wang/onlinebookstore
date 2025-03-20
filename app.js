// Import required modules 
const express = require('express');
const path = require('path');
const dotenv = require('dotenv');
const session = require('express-session');
const bodyParser = require('body-parser');

// Load environment variables 
dotenv.config();

// Initialize Express app (Declare `app` only once)
const app = express();
const PORT = process.env.PORT || 3000;

// Set view engine to EJS 
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files 
app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// Session management
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Import routes 
const indexRoutes = require('./routes/index'); // Ensure this file exists
const authRoutes = require('./routes/authRoutes');
const db = require('./config/db'); // Import database connection

// Define routes
app.use('/', indexRoutes);
app.use('/auth', authRoutes);

// Database test route
app.get('/db-test', async (req, res) => {
    try {
        const result = await db.one('SELECT NOW() AS current_time');
        res.json({ message: 'Database connected successfully', time: result.current_time });
    } catch (err) {
        res.status(500).json({ error: 'Database connection failed', details: err.message });
    }
});

// Start the server (Should only appear once)
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
