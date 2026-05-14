// messenger.js
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'dev-secret-change-me-in-production';

// Создаём папки
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');
if (!fs.existsSync('./public')) fs.mkdirSync('./public');

// Инициализация БД
const db = new Database('chat.db');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT UNIQUE, 
    password_hash TEXT, 
    status TEXT DEFAULT 'offline', 
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    sender_id INTEGER, 
    receiver_id INTEGER, 
    content TEXT, 
    file_path TEXT, 
    file_type TEXT,
    file_name TEXT,
    is_read INTEGER DEFAULT 0, 
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender_id, receiver_id);
  CREATE INDEX IF NOT EXISTS idx_msg_unread ON messages(receiver_id, is_read);
`);

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use('/uploads', express.static('./uploads'));
app.use(express.static('./public'));

// Настройка multer для загрузки файлов
const storage = multer.diskStorage({ 
  destination: './uploads', 
  filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`) 
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// Middleware авторизации
const auth = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { 
    req.user = jwt.verify(token, JWT_SECRET); 
    next(); 
  } catch { 
    res.status(401).json({ error: 'Invalid token' }); 
  }
};

// 🔐 Auth Routes
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username?.trim() || !password) return res.status(400).json({ error: 'Заполните все поля' });
  const hash = await bcrypt.hash(password, 10);
  try {
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username.trim(), hash);
    res.json({ success: true });
  } catch { res.status(409).json({ error: 'Имя уже занято' }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user || !await bcrypt.compare(password, user.password_hash)) 
    return res.status(401).json({ error: 'Неверные данные' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', token, { 
  httpOnly: true, 
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  secure: process.env.NODE_ENV === 'production', // true на Render (HTTPS), false локально
  maxAge: 30 * 24 * 60 * 60 * 1000 
});
  res.json({ id: user.id, username: user.username });
});

app.post('/api/logout', (_, res) => { 
  res.clearCookie('token').json({ success: true }); 
});

// 🔍 Поиск пользователей
app.get('/api/users', auth, (req, res) => {
  const q = req.query.q || '';
  const users = db.prepare(
    'SELECT id, username, status, last_seen FROM users WHERE id != ? AND username LIKE ? ORDER BY username'
  ).all(req.user.id, `%${q}%`);
  res.json(users);
});

// 💬 История сообщений
app.get('/api/messages/:userId', auth, (req, res) => {
  const msgs = db.prepare(`
    SELECT m.*, u.username as sender_name FROM messages m 
    JOIN users u ON u.id = m.sender_id 
    WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
    ORDER BY m.created_at ASC LIMIT 100
  `).all(req.user.id, req.params.userId, req.params.userId, req.user.id);
  res.json(msgs);
});

// 📂 Загрузка файлов
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Нет файла' });
  res.json({ 
    url: `/uploads/${req.file.filename}`, 
    type: req.file.mimetype, 
    name: req.file.originalname 
  });
});

// 🌐 Socket.IO логика
const sockets = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('auth_required'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { next(new Error('invalid_token')); }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  sockets.set(userId, socket);
  
  db.prepare('UPDATE users SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?')
    .run('online', userId);
  io.emit('user_status', { userId, status: 'online' });

  socket.on('send_message', ({ receiverId, content, fileUrl, fileType, fileName }) => {
    const stmt = db.prepare(
      'INSERT INTO messages (sender_id, receiver_id, content, file_path, file_type, file_name) VALUES (?, ?, ?, ?, ?, ?)'
    );
    const { lastInsertRowid } = stmt.run(
      userId, receiverId, content || '', fileUrl || null, fileType || null, fileName || null
    );
    const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(lastInsertRowid);

    const targetSocket = sockets.get(receiverId);
    if (targetSocket) targetSocket.emit('new_message', msg);
    socket.emit('message_sent', msg);
  });

  socket.on('mark_read', ({ senderId }) => {
    db.prepare(
      'UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0'
    ).run(senderId, userId);
    const target = sockets.get(senderId);
    if (target) target.emit('messages_read', { readerId: userId });
  });

  socket.on('disconnect', () => {
    db.prepare('UPDATE users SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?')
      .run('offline', userId);
    sockets.delete(userId);
    io.emit('user_status', { userId, status: 'offline' });
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Мессенджер запущен: http://localhost:${PORT}`);
});
