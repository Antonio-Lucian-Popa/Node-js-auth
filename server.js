const express = require('express');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { PrismaClient } = require('@prisma/client');

// Initialize modules
dotenv.config();
const app = express();
const prisma = new PrismaClient();

// Middleware
app.use(express.json());

// Endpoint pentru înregistrare
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Hash parola
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        isVerified: true
      },
    });

    // Creare token de confirmare
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Trimitere email de confirmare
   // await sendConfirmationEmail(user.email, token);

    res.status(201).json({ message: 'User created. Please confirm your email.', token: token });
  } catch (error) {
    res.status(500).json({ error: 'User already exists.' });
  }
});

// Endpoint pentru confirmarea contului
app.get('/confirm/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await prisma.user.update({
      where: { id: decoded.userId },
      data: { isVerified: true },
    });

    res.status(200).json({ message: 'Account confirmed.' });
  } catch (error) {
    res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// Endpoint pentru autentificare
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  if (!user.isVerified) {
    return res.status(400).json({ error: 'Please confirm your email.' });
  }

  const isValidPassword = await bcrypt.compare(password, user.password);

  if (!isValidPassword) {
    return res.status(401).json({ error: 'Invalid password.' });
  }

  // Generare token JWT
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

  res.status(200).json({ message: 'Login successful.', token: token });
});

// Endpoint pentru a obține datele la toti utilizatorii
app.get('/users', authenticateToken, async (req, res) => {
  const users = await prisma.user.findMany();

  res.status(200).json(users);
});

// Functie care verifica daca utilizatorul este autentificat
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden.' });
    }

    req.user = user;
    next();
  });
}

// Funcție de trimitere a emailului de confirmare
async function sendConfirmationEmail(email, token) {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const url = `http://localhost:3000/confirm/${token}`;
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Confirm Your Account',
    html: `<p>Please confirm your account by clicking <a href="${url}">here</a>.</p>`,
  });
}

// Pornire server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
