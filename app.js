// User Dashboard Web Server
// This application displays user sign-up and last login information from a SQLite database

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const moment = require('moment');

// Initialize Express app
const app = express();
const PORT = 3000;

// Set up middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Initialize database connection
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error connecting to database:', err.message);
  } else {
    console.log('Connected to the SQLite database');
    
    // Create users table if it doesn't exist
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        signup_date TEXT NOT NULL,
        last_login TEXT NOT NULL
      )
    `, (err) => {
      if (err) {
        console.error('Error creating table:', err.message);
      } else {
        console.log('Users table ready');
        
        // Insert some sample data if the table is empty
        db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
          if (err) {
            console.error('Error checking users count:', err.message);
            return;
          }
          
          if (row.count === 0) {
            const sampleUsers = [
              ['john_doe', 'john@example.com', 'password123', '2024-02-15 10:30:00', '2024-04-20 15:45:00'],
              ['jane_smith', 'jane@example.com', 'securepass', '2024-03-22 14:20:00', '2024-04-27 09:15:00'],
              ['bob_jackson', 'bob@example.com', 'bobpass456', '2024-01-05 08:10:00', '2024-04-15 12:30:00']
            ];
            
            const insertStmt = db.prepare('INSERT INTO users (username, email, password, signup_date, last_login) VALUES (?, ?, ?, ?, ?)');
            sampleUsers.forEach(user => {
              insertStmt.run(user, (err) => {
                if (err) console.error('Error inserting sample user:', err.message);
              });
            });
            insertStmt.finalize();
            console.log('Sample users inserted');
          }
        });
      }
    });
  }
});

// Routes
app.get('/', (req, res) => {
  // Get all users from database
  db.all('SELECT id, username, email, signup_date, last_login FROM users', (err, users) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      return res.status(500).send('Database error');
    }
    
    // Format dates for display
    const formattedUsers = users.map(user => {
      return {
        ...user,
        formatted_signup: moment(user.signup_date).format('MMMM Do YYYY, h:mm:ss a'),
        formatted_last_login: moment(user.last_login).format('MMMM Do YYYY, h:mm:ss a')
      };
    });
    
    res.render('index', { users: formattedUsers });
  });
});

// API route to get users as JSON
app.get('/api/users', (req, res) => {
  db.all('SELECT id, username, email, signup_date, last_login FROM users', (err, users) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(users);
  });
});

// Mock login route to update last login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  // Check if user exists and password matches
  db.get('SELECT id, password FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('Error during login:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login time
    const now = new Date().toISOString();
    db.run('UPDATE users SET last_login = ? WHERE id = ?', [now, user.id], (err) => {
      if (err) {
        console.error('Error updating last login:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({ success: true, message: 'Login successful' });
    });
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Close database connection when the process ends
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed');
    }
    process.exit(0);
  });
});