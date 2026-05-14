const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-me';

const app = express();
const server = http.createServer(app);

// Middleware
app.use(cors({ 
  origin: true,
  credentials: true 
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database
const db = new sqlite3.Database('./chat.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    status TEXT DEFAULT 'offline',
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    content TEXT,
    is_read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Socket.IO
const io = new Server(server, {
  cors: {
    origin: true,
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['polling', 'websocket']
});

const userSockets = new Map();

// Auth middleware
const auth = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }
  
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Fill all fields' });
  
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
    [username.trim(), hash], 
    function(err) {
      if (err) return res.status(409).json({ error: 'Username exists' });
      res.json({ success: true });
    }
  );
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username.trim()], async (err, user) => {
    if (!user) return res.status(401).json({ error: 'User not found' });
    
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid password' });
    
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    
    // Cookie settings for HTTPS
    res.cookie('token', token, { 
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000 
    });
    
    res.json({ id: user.id, username: user.username });
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { path: '/' }).json({ success: true });
});

app.get('/api/users', auth, (req, res) => {
  const q = req.query.q || '';
  db.all(
    'SELECT id, username, status, last_seen FROM users WHERE id != ? AND username LIKE ? ORDER BY username',
    [req.user.id, `%${q}%`],
    (err, users) => res.json(err ? [] : users)
  );
});

app.get('/api/messages/:userId', auth, (req, res) => {
  const otherId = req.params.userId;
  db.all(
    `SELECT m.*, u.username as sender_name FROM messages m
     JOIN users u ON u.id = m.sender_id
     WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
     ORDER BY m.created_at ASC LIMIT 100`,
    [req.user.id, otherId, otherId, req.user.id],
    (err, messages) => res.json(err ? [] : messages)
  );
});

// Socket.IO
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Invalid token'));
    socket.user = user;
    next();
  });
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  console.log(`✅ Connected: ${socket.user.username} (${userId})`);
  
  userSockets.set(userId, socket.id);
  db.run('UPDATE users SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?', ['online', userId]);
  io.emit('user_status', { userId, status: 'online' });
  
  socket.on('send_message', ({ receiverId, content }) => {
    console.log(`📩 ${userId} → ${receiverId}:`, content);
    
    db.run(
      'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
      [userId, receiverId, content || ''],
      function(err) {
        if (err) return socket.emit('error', { message: 'Failed' });
        
        db.get('SELECT * FROM messages WHERE id = ?', [this.lastID], (err, msg) => {
          if (!msg) return;
          msg.sender_name = socket.user.username;
          
          const receiverSocketId = userSockets.get(Number(receiverId));
          if (receiverSocketId) {
            const receiverSocket = io.sockets.sockets.get(receiverSocketId);
            if (receiverSocket) receiverSocket.emit('new_message', msg);
          }
          
          socket.emit('message_sent', msg);
        });
      }
    );
  });
  
  socket.on('mark_read', ({ senderId }) => {
    db.run(
      'UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0',
      [senderId, userId]
    );
  });
  
  socket.on('disconnect', () => {
    console.log(`❌ Disconnected: ${socket.user.username}`);
    userSockets.delete(userId);
    db.run('UPDATE users SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?', ['offline', userId]);
    io.emit('user_status', { userId, status: 'offline' });
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
