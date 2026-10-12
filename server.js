const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const PORT = 3001;

// CORS configuration matching React Dev Server
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());

const db = new sqlite3.Database('./ngilo.db', (err) => {
    if (err) console.error('DB Error:', err.message);
    else console.log('Connected to ngilo.db');
});

db.run('CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT)');
db.run(`CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  message TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
)`);

// SIGNUP — Account registration handling with strict inputs validation
app.post('/api/signup', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || username.trim() === "" || password.trim() === "") {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Validation Check: Username must start with a Capital Letter
    const firstChar = username.charAt(0);
    if (firstChar !== firstChar.toUpperCase() || firstChar.toLowerCase() === firstChar.toUpperCase()) {
        return res.status(400).json({ message: 'Username must start with a capital letter!' });
    }

    // Validation Check: Password must contain at least one number
    const hasNumber = /\d/.test(password);
    if (!hasNumber) {
        return res.status(400).json({ message: 'Password must contain at least one number!' });
    }

    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const userId = uuidv4();

        db.run(
            'INSERT INTO users (user_id, username, password) VALUES (?, ?, ?)',
            [userId, username, hashedPassword],
            function (err) {
                if (err) {
                    return res.status(400).json({ message: 'Username already exists.' });
                }
                res.status(200).json({ userId, username });
            }
        );
    } catch (error) {
        res.status(500).json({ message: 'Server error during signup.' });
    }
});

// LOGIN — Session initialization endpoint with validation feedback
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || username.trim() === "" || password.trim() === "") {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Server error.' });
        }
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const isMatch = bcrypt.compareSync(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        res.status(200).json({ userId: user.user_id, username: user.username });
    });
});

// POST METHOD: Send Anonymous Message into SQLite DB
app.post('/api/messages/send', (req, res) => {
    const { receiverId, content } = req.body;

    if (!content || content.trim() === '') {
        return res.status(400).json({ message: 'Message content cannot be empty.' });
    }
    if (!receiverId) {
        return res.status(400).json({ message: 'Receiver identity is missing.' });
    }

    db.run(
        'INSERT INTO messages (user_id, message) VALUES (?, ?)',
        [receiverId, content],
        function (err) {
            if (err) {
                console.error('Database insertion error:', err.message);
                return res.status(500).json({ message: 'Failed to save message to database.' });
            }
            res.status(200).json({ success: true, message: 'Message sent successfully!' });
        }
    );
});

// GET METHOD: Fetch and display received messages for Inbox tracking
app.get('/api/messages/:userId', (req, res) => {
    const { userId } = req.params;

    if (!userId) {
        return res.status(400).json({ message: 'User identity parameters are missing.' });
    }

    db.all(
        'SELECT id, message, timestamp FROM messages WHERE user_id = ? ORDER BY timestamp DESC',
        [userId],
        (err, rows) => {
            if (err) {
                console.error('Database retrieval error:', err.message);
                return res.status(500).json({ message: 'Failed to retrieve messages from database.' });
            }
            res.status(200).json(rows);
        }
    );
});

// POST METHOD: Persist updated profile username values to SQLite database
app.post('/api/user/update', (req, res) => {
    const { userId, newUsername } = req.body;

    if (!userId || !newUsername || newUsername.trim() === "") {
        return res.status(400).json({ message: 'User identity and new username are required.' });
    }

    // Capital Letter Check on the edited input value
    const firstChar = newUsername.charAt(0);
    if (firstChar !== firstChar.toUpperCase() || firstChar.toLowerCase() === firstChar.toUpperCase()) {
        return res.status(400).json({ message: 'Username must start with a capital letter!' });
    }

    db.run(
        'UPDATE users SET username = ? WHERE user_id = ?',
        [newUsername, userId],
        function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ message: 'Username already exists.' });
                }
                console.error('Profile update error:', err.message);
                return res.status(500).json({ message: 'Failed to update username.' });
            }
            res.status(200).json({ success: true, message: 'Username updated successfully!' });
        }
    );
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
