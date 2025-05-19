require('dotenv').config();
const express = require('express');
const neo4j = require('neo4j-driver');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const rateLimit = require('express-rate-limit');
const fs = require('fs');

const app = express();

// Middleware Configuration
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Directory Setup
const requiredDirs = [
  path.join(__dirname, 'uploads'),
  path.join(__dirname, 'public')
];

requiredDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Security Middleware
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts. Please try again later.'
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

// Database Connection
const driver = neo4j.driver(
  process.env.NEO4J_URI,
  neo4j.auth.basic(process.env.NEO4J_USER, process.env.NEO4J_PASSWORD),
  { 
    maxConnectionPoolSize: 10,
    connectionTimeout: 30000,
    connectionAcquisitionTimeout: 60000
  }
);

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'uploads'));
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|mp4|mov|avi|webm|mkv/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only images and videos are allowed (jpeg, jpg, png, gif, mp4, mov, avi, webm, mkv)'));
  },
  limits: { 
    fileSize: 50 * 1024 * 1024,
    files: 1 
  }
});

// Authentication Middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token.' });
    }
    req.user = decoded;
    next();
  });
};

// API Routes
app.post('/api/register', upload.fields([
  { name: 'avatar', maxCount: 1 },
  { name: 'schoolId', maxCount: 1 }
]), async (req, res) => {
  const { username, password, email, userType, course, institution } = req.body;
  const files = req.files;
  
  // Validate required fields
  if (!username || !password || !email || !userType || !course || !institution) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  
  // Password validation
  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters.' });
  }

  // Email domain validation
  const blockedDomains = ['gmail.com', 'yahoo.com', 'outlook.com'];
  const domain = email.split('@')[1];
  if (blockedDomains.includes(domain.toLowerCase())) {
    if (!files?.schoolId) {
      return res.status(400).json({ message: 'School ID verification required for personal email domains' });
    }
  }

  const session = driver.session();
  try {
    // Check existing user
    const { records } = await session.run(
      `MATCH (u:User) 
       WHERE u.username = $username OR u.email = $email 
       RETURN count(u) as count`,
      { username, email }
    );

    if (records[0].get('count').toNumber() > 0) {
      return res.status(400).json({ message: 'Username or email already exists.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user with additional fields
    await session.run(
      `CREATE (u:User {
        username: $username, 
        password: $password, 
        email: $email,
        userType: $userType,
        course: $course,
        institution: $institution,
        avatar: $avatar,
        schoolId: $schoolId,
        createdAt: datetime()
      }) RETURN u`,
      {
        username,
        password: hashedPassword,
        email,
        userType,
        course,
        institution,
        avatar: files.avatar ? files.avatar[0].filename : 'default-avatar.png',
        schoolId: files.schoolId ? files.schoolId[0].filename : null
      }
    );

    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Error during registration.' });
  } finally {
    await session.close();
  }
});

// Modified Search Route with Course Filtering
app.get('/api/search/users', authenticate, async (req, res) => {
  const { username, course } = req.query;
  
  if (!username || username.trim().length < 2) {
    return res.status(400).json({ message: 'Search query must be at least 2 characters.' });
  }

  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (u:User)
       WHERE toLower(u.username) CONTAINS toLower($username)
       ${course ? 'AND u.course = $course' : ''}
       RETURN u.username as username, u.avatar as avatar, u.course as course, u.userType as userType
       LIMIT 10`,
      { 
        username: username.trim(),
        course: course ? course.trim() : null
      }
    );

    const users = result.records.map(record => ({
      username: record.get('username'),
      avatar: record.get('avatar') || 'default-avatar.png',
      course: record.get('course'),
      userType: record.get('userType')
    }));

    res.json(users);
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ message: 'Error searching users.' });
  } finally {
    await session.close();
  }
});

// Enhanced Follow Route
app.post('/api/users/:username/follow', authenticate, async (req, res) => {
  const { username } = req.params;
  const session = driver.session();

  try {
    // Check existing follow relationship
    const check = await session.run(
      `MATCH (u:User {username: $currentUser})-[r:FOLLOWS]->(t:User {username: $targetUser})
       RETURN r`,
      { 
        currentUser: req.user.username, 
        targetUser: username 
      }
    );

    if (check.records.length > 0) {
      // Unfollow
      await session.run(
        `MATCH (u:User {username: $currentUser})-[r:FOLLOWS]->(t:User {username: $targetUser})
         DELETE r`,
        { 
          currentUser: req.user.username, 
          targetUser: username 
        }
      );
      res.json({ success: true, following: false });
    } else {
      // Follow
      await session.run(
        `MATCH (a:User {username: $currentUser}), (b:User {username: $targetUser})
         CREATE (a)-[:FOLLOWS]->(b)`,
        { 
          currentUser: req.user.username, 
          targetUser: username 
        }
      );
      res.json({ success: true, following: true });
    }
  } catch (err) {
    console.error('Follow error:', err);
    res.status(500).json({ message: 'Error following user.' });
  } finally {
    await session.close();
  }
});

// Keep all other existing routes unchanged
// [Previous routes for login, profile, posts, comments, etc. remain the same]

// Error handling middleware and server startup
app.use((err, req, res, next) => {
  console.error('Global error:', err.stack);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ 
      message: `File upload error: ${err.message}` 
    });
  }
  
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

process.on('SIGTERM', () => {
  server.close(() => {
    driver.close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  server.close(() => {
    driver.close();
    process.exit(0);
  });
});
