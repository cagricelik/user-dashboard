// User Dashboard Web Server with Admin Panel
// This application displays user sign-up and last login information from a SQLite database
// Includes admin authentication and user management capabilities

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const moment = require('moment');
const session = require('express-session');
const bcrypt = require('bcrypt');

// Initialize Express app
const app = express();
const PORT = 3000;

// Set up middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Set up session middleware
app.use(session({
  secret: 'admin-dashboard-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // 1 hour
}));

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
        last_login TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
      )
    `, (err) => {
      if (err) {
        console.error('Error creating users table:', err.message);
      } else {
        console.log('Users table ready');
        
        // Check if admin user exists, if not create one
        db.get('SELECT COUNT(*) as count FROM users WHERE is_admin = 1', async (err, row) => {
          if (err) {
            console.error('Error checking admin user:', err.message);
            return;
          }
          
          if (row.count === 0) {
            // Create admin user
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const now = new Date().toISOString();
            
            db.run(
              'INSERT INTO users (username, email, password, signup_date, last_login, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
              ['admin', 'admin@example.com', hashedPassword, now, now, 1],
              (err) => {
                if (err) {
                  console.error('Error creating admin user:', err.message);
                } else {
                  console.log('Admin user created with username: admin and password: admin123');
                }
              }
            );
          }
        });
        
        // Insert some sample users if the table is empty (non-admin users)
        db.get('SELECT COUNT(*) as count FROM users WHERE is_admin = 0', async (err, row) => {
          if (err) {
            console.error('Error checking users count:', err.message);
            return;
          }
          
          if (row.count === 0) {
            // Create sample users with bcrypt hashed passwords
            const createSampleUser = async (username, email, password) => {
              const hashedPassword = await bcrypt.hash(password, 10);
              const signupDate = new Date();
              signupDate.setDate(signupDate.getDate() - Math.floor(Math.random() * 100)); // Random date within last 100 days
              
              const lastLoginDate = new Date(signupDate);
              lastLoginDate.setDate(lastLoginDate.getDate() + Math.floor(Math.random() * (new Date() - signupDate) / (1000 * 60 * 60 * 24)));
              
              return new Promise((resolve, reject) => {
                db.run(
                  'INSERT INTO users (username, email, password, signup_date, last_login, is_admin) VALUES (?, ?, ?, ?, ?, 0)',
                  [username, email, hashedPassword, signupDate.toISOString(), lastLoginDate.toISOString()],
                  (err) => {
                    if (err) {
                      console.error('Error inserting sample user:', err.message);
                      reject(err);
                    } else {
                      resolve();
                    }
                  }
                );
              });
            };
            
            try {
              await createSampleUser('john_doe', 'john@example.com', 'password123');
              await createSampleUser('jane_smith', 'jane@example.com', 'securepass');
              await createSampleUser('bob_jackson', 'bob@example.com', 'bobpass456');
              console.log('Sample users inserted');
            } catch (error) {
              console.error('Error creating sample users:', error);
            }
          }
        });
      }
    });
  }
});

// Middleware to check if user is authenticated as admin
const isAdmin = (req, res, next) => {
  if (req.session.isAdmin) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => {
  // If admin is logged in, show admin view, otherwise show public view
  if (req.session.isAdmin) {
    res.redirect('/admin/dashboard');
  } else {
    // Get all users from database (public view - limited data)
    db.all('SELECT id, username, signup_date, last_login FROM users', (err, users) => {
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
  }
});

// Login routes
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.render('login', { error: 'Username and password are required' });
  }
  
  // Find the user in the database
  db.get('SELECT * FROM users WHERE username = ? AND is_admin = 1', [username], async (err, user) => {
    if (err) {
      console.error('Login error:', err.message);
      return res.render('login', { error: 'Database error' });
    }
    
    if (!user) {
      return res.render('login', { error: 'Invalid username or password' });
    }
    
    // Compare passwords
    try {
      const match = await bcrypt.compare(password, user.password);
      
      if (match) {
        // Update last login time
        const now = new Date().toISOString();
        db.run('UPDATE users SET last_login = ? WHERE id = ?', [now, user.id]);
        
        // Set session
        req.session.isAdmin = true;
        req.session.userId = user.id;
        req.session.username = user.username;
        
        res.redirect('/admin/dashboard');
      } else {
        res.render('login', { error: 'Invalid username or password' });
      }
    } catch (error) {
      console.error('Password comparison error:', error);
      res.render('login', { error: 'Authentication error' });
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.redirect('/login');
  });
});

// Admin routes
app.get('/admin/dashboard', isAdmin, (req, res) => {
  db.all('SELECT * FROM users', (err, users) => {
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
    
    res.render('admin/dashboard', { 
      users: formattedUsers,
      username: req.session.username,
      userId: req.session.userId
    });
  });
});

// Create user route
app.get('/admin/users/create', isAdmin, (req, res) => {
  res.render('admin/user-form', { 
    user: null, 
    action: 'create',
    error: null,
    username: req.session.username
  });
});

app.post('/admin/users/create', isAdmin, async (req, res) => {
  const { username, email, password, is_admin } = req.body;
  
  if (!username || !email || !password) {
    return res.render('admin/user-form', { 
      user: req.body, 
      action: 'create',
      error: 'Username, email and password are required',
      username: req.session.username
    });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();
    const isAdminValue = is_admin ? 1 : 0;
    
    db.run(
      'INSERT INTO users (username, email, password, signup_date, last_login, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
      [username, email, hashedPassword, now, now, isAdminValue],
      (err) => {
        if (err) {
          console.error('Error creating user:', err.message);
          return res.render('admin/user-form', { 
            user: req.body, 
            action: 'create',
            error: `Error creating user: ${err.message}`,
            username: req.session.username
          });
        }
        
        res.redirect('/admin/dashboard');
      }
    );
  } catch (error) {
    console.error('Error hashing password:', error);
    res.render('admin/user-form', { 
      user: req.body, 
      action: 'create',
      error: 'Error creating user',
      username: req.session.username
    });
  }
});

// Edit user route
app.get('/admin/users/edit/:id', isAdmin, (req, res) => {
  const userId = req.params.id;
  
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      console.error('Error fetching user:', err.message);
      return res.redirect('/admin/dashboard');
    }
    
    if (!user) {
      return res.redirect('/admin/dashboard');
    }
    
    res.render('admin/user-form', { 
      user, 
      action: 'edit',
      error: null,
      username: req.session.username
    });
  });
});

app.post('/admin/users/edit/:id', isAdmin, async (req, res) => {
  const userId = req.params.id;
  const { username, email, password, is_admin } = req.body;
  
  if (!username || !email) {
    return res.render('admin/user-form', { 
      user: { ...req.body, id: userId }, 
      action: 'edit',
      error: 'Username and email are required',
      username: req.session.username
    });
  }
  
  try {
    const isAdminValue = is_admin ? 1 : 0;
    
    if (password) {
      // Update with new password
      const hashedPassword = await bcrypt.hash(password, 10);
      
      db.run(
        'UPDATE users SET username = ?, email = ?, password = ?, is_admin = ? WHERE id = ?',
        [username, email, hashedPassword, isAdminValue, userId],
        (err) => {
          if (err) {
            console.error('Error updating user:', err.message);
            return res.render('admin/user-form', { 
              user: { ...req.body, id: userId }, 
              action: 'edit',
              error: `Error updating user: ${err.message}`,
              username: req.session.username
            });
          }
          
          res.redirect('/admin/dashboard');
        }
      );
    } else {
      // Update without changing password
      db.run(
        'UPDATE users SET username = ?, email = ?, is_admin = ? WHERE id = ?',
        [username, email, isAdminValue, userId],
        (err) => {
          if (err) {
            console.error('Error updating user:', err.message);
            return res.render('admin/user-form', { 
              user: { ...req.body, id: userId }, 
              action: 'edit',
              error: `Error updating user: ${err.message}`,
              username: req.session.username
            });
          }
          
          res.redirect('/admin/dashboard');
        }
      );
    }
  } catch (error) {
    console.error('Error updating user:', error);
    res.render('admin/user-form', { 
      user: { ...req.body, id: userId }, 
      action: 'edit',
      error: 'Error updating user',
      username: req.session.username
    });
  }
});

// Delete user route
app.post('/admin/users/delete/:id', isAdmin, (req, res) => {
  const userId = req.params.id;
  
  // Prevent admins from deleting themselves
  if (parseInt(userId) === req.session.userId) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  
  db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
    if (err) {
      console.error('Error deleting user:', err.message);
      return res.status(500).json({ error: 'Error deleting user' });
    }
    
    res.json({ success: true });
  });
});

// API route to get users as JSON
app.get('/api/users', (req, res) => {
  db.all('SELECT id, username, email, signup_date, last_login, is_admin FROM users', (err, users) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(users);
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