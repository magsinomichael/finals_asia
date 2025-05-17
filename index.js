import express from 'express'; //server
import bodyParser from 'body-parser'; //Middleware
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';


const app = express();
const port = 3000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Start server
app.listen(port, () => {
  console.log('Running on port ' + port);
  console.log('Server is running on http://localhost:' + port);
});

app.get('/api', (req, res) => {
  res.send('REST API is working');
});

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'blog_db'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL!');
});

// Register a user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO login_tbl (username, password) VALUES (?, ?)';

    db.query(sql, [username, hashedPassword], (err, result) => {
      if (err) {
        console.error('Database error:', err.message);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }

      console.log('User registered:', { username, hashedPassword });
      res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    });
  } catch (error) {
    console.error('Error during registration:', error.message);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Login a user
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const sql = 'SELECT * FROM login_tbl WHERE username = ?';
  db.query(sql, [username], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', token });
  });
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.user = user;
    next();
  });
};

// Example protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'This is a protected route', user: req.user });
});


// Retrieve all blog posts (protected)
app.get('/posts', authenticateToken, (req, res) => {
  db.query('SELECT * FROM posts', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

// Retrieve specific blog post (protected)
app.get('/posts/:id', authenticateToken, (req, res) => {
  db.query('SELECT * FROM posts WHERE id = ?', [req.params.id], (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(404).send({ message: 'Post not found' });
    res.json(results[0]);
  });
});

// Create new blog post (protected)
app.post('/posts', authenticateToken, (req, res) => {
  const { title, content, author } = req.body;
  const sql = 'INSERT INTO posts (title, content, author) VALUES (?, ?, ?)';
  db.query(sql, [title, content, author], (err, result) => {
    if (err) return res.status(500).send(err);
    res.status(201).json({ id: result.insertId, title, content, author });
  });
});

// Update blog post (protected)
app.put('/posts/:id', authenticateToken, (req, res) => {
  const { title, content, author } = req.body;
  const sql = 'UPDATE posts SET title = ?, content = ?, author = ? WHERE id = ?';
  db.query(sql, [title, content, author, req.params.id], (err) => {
    if (err) return res.status(500).send(err);
    res.json({ id: req.params.id, title, content, author });
  });
});

// Delete blog post (protected)
app.delete('/posts/:id', authenticateToken, (req, res) => {
  db.query('DELETE FROM posts WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).send(err);
    res.json({ message: 'Post deleted', id: req.params.id });
  });
});


