const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'secret_key';

let users = [];
let messages = [];

// Load users if exist
if (fs.existsSync('users.json')) {
  users = JSON.parse(fs.readFileSync('users.json'));
}

// Load messages if exist
if (fs.existsSync('messages.json')) {
  messages = JSON.parse(fs.readFileSync('messages.json'));
}

// Register new user
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'Email already exists' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, email, password: hashedPassword, banned: false });
  fs.writeFileSync('users.json', JSON.stringify(users));
  res.status(201).json({ message: 'User registered successfully' });
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  if (user.banned) return res.status(403).json({ message: 'User is banned' });
  
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: 'Invalid credentials' });
  
  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1d' });
  res.json({ token, username: user.username });
});

// Send Message
app.post('/message', (req, res) => {
  const { token, content } = req.body;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const sender = users.find(u => u.email === decoded.email);
    if (!sender || sender.banned) return res.status(403).json({ message: 'User is banned' });

    messages.push({ sender: sender.username, email: sender.email, content, timestamp: new Date() });
    fs.writeFileSync('messages.json', JSON.stringify(messages));
    res.status(201).json({ message: 'Message sent' });
  } catch (err) {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// Get All Messages (Admin Only)
app.post('/admin/messages', (req, res) => {
  const { email, password } = req.body;
  if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
    res.json(messages);
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// Ban or Unban user
app.post('/admin/ban', (req, res) => {
  const { email, password, userEmail, ban } = req.body;
  if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
    const user = users.find(u => u.email === userEmail);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.banned = ban;
    fs.writeFileSync('users.json', JSON.stringify(users));
    res.json({ message: `User ${ban ? 'banned' : 'unbanned'} successfully` });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// Change Admin Email or Password
app.post('/admin/change', (req, res) => {
  const { email, password, newEmail, newPassword } = req.body;
  if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
    if (newEmail) process.env.ADMIN_EMAIL = newEmail;
    if (newPassword) process.env.ADMIN_PASSWORD = newPassword;
    res.json({ message: 'Admin credentials updated' });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// Home
app.get('/', (req, res) => {
  res.send('Server is running...');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
