const bcrypt = require('bcryptjs');
const db = require('../config/db');
// Signup
exports.registerUser = async (req, res) => {
const { name, email, password } = req.body;
const hashedPassword = await bcrypt.hash(password, 10);
try {
await db.none('INSERT INTO users (name, email, password) VALUES($1, $2, $3)', [name, email, hashedPassword]);
res.status(201).json({ message: 'User registered successfully' });
} catch (err) {
res.status(500).json({ error: 'Error registering user' });
}
};
// Login
// Login
exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    try {
      const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      req.session.user = { id: user.id, name: user.name, email: user.email };
  
      // Instead of sending the user in the redirect, you can:
      // Option 1: Redirect to home page (without user object in redirect)
      res.redirect('/home');
      
      // Option 2: Send JSON with user data (if you don't want to redirect)
      // res.status(200).json({ message: 'Login successful', user: req.session.user });
  
    } catch (err) {
      console.error("Error:", err.message);
      res.status(500).json({ error: 'Error logging in' });
    }
  };
  
    // Logout
    exports.logoutUser = (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out successfully' });
    };