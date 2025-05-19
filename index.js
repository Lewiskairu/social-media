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
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters.' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const session = driver.session();

  try {
    const { records } = await session.run(
      `MATCH (u:User) 
       WHERE u.username = $username OR u.email = $email 
       RETURN count(u) as count`,
      { username, email }
    );

    if (records[0].get('count').toNumber() > 0) {
      return res.status(400).json({ message: 'Username or email already exists.' });
    }

    await session.run(
      `CREATE (u:User {
        username: $username, 
        password: $password, 
        email: $email,
        createdAt: datetime(),
        avatar: 'default-avatar.png'
      }) RETURN u`,
      { username, password: hashedPassword, email }
    );

    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Error during registration.' });
  } finally {
    await session.close();
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (u:User {username: $username}) 
       RETURN u`,
      { username }
    );

    if (result.records.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
    
    const user = result.records[0].get('u').properties;
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
    
    const token = jwt.sign(
      { username: user.username }, 
      process.env.JWT_SECRET, 
      { expiresIn: '2h' }
    );
    
    res.json({ 
      token,
      username: user.username,
      avatar: user.avatar || 'default-avatar.png'
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login error.' });
  } finally {
    await session.close();
  }
});

// Profile Routes
app.get('/api/profile/me', authenticate, async (req, res) => {
  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (u:User {username: $username})
       RETURN u`,
      { username: req.user.username }
    );

    if (result.records.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    
    const user = result.records[0].get('u').properties;
    res.json({
      username: user.username,
      email: user.email,
      avatar: user.avatar || 'default-avatar.png',
      createdAt: user.createdAt
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ message: 'Error fetching profile.' });
  } finally {
    await session.close();
  }
});

app.get('/api/profile/:username', authenticate, async (req, res) => {
  const { username } = req.params;
  const session = driver.session();
  
  try {
    const result = await session.run(
      `MATCH (u:User {username: $username})
       RETURN u`,
      { username }
    );

    if (result.records.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    
    const user = result.records[0].get('u').properties;
    res.json({
      username: user.username,
      avatar: user.avatar || 'default-avatar.png',
      createdAt: user.createdAt
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ message: 'Error fetching profile.' });
  } finally {
    await session.close();
  }
});

// Post Routes
app.post('/api/posts', authenticate, upload.single('media'), async (req, res) => {
  const { content } = req.body;
  
  if (!content || content.trim().length === 0) {
    return res.status(400).json({ message: 'Post content is required.' });
  }

  const session = driver.session();
  try {
    const mediaUrl = req.file ? req.file.filename : null;
    
    const result = await session.run(
      `MATCH (u:User {username: $username})
       CREATE (p:Post {
         content: $content, 
         media: $mediaUrl,
         createdAt: datetime()
       })
       CREATE (u)-[:CREATED]->(p)
       RETURN p, u`,
      { 
        username: req.user.username, 
        content: content.trim(),
        mediaUrl 
      }
    );

    const post = result.records[0].get('p').properties;
    const user = result.records[0].get('u').properties;
    
    res.status(201).json({
      id: post.elementId,
      content: post.content,
      media: post.media,
      createdAt: post.createdAt,
      user: {
        username: user.username,
        avatar: user.avatar || 'default-avatar.png'
      }
    });
  } catch (err) {
    console.error('Post creation error:', err);
    res.status(500).json({ message: 'Error creating post.' });
  } finally {
    await session.close();
  }
});

app.post('/api/posts/:id/like', authenticate, async (req, res) => {
  const { id } = req.params;
  const session = driver.session();
  
  try {
    // Check if already liked
    const likeCheck = await session.run(
      `MATCH (u:User {username: $username})-[r:LIKED]->(p:Post)
       WHERE elementId(p) = $id 
       RETURN r`,
      { username: req.user.username, id }
    );

    if (likeCheck.records.length > 0) {
      // Unlike
      await session.run(
        `MATCH (u:User {username: $username})-[r:LIKED]->(p:Post)
         WHERE elementId(p) = $id 
         DELETE r`,
        { username: req.user.username, id }
      );
    } else {
      // Like
      await session.run(
        `MATCH (u:User {username: $username}), (p:Post)
         WHERE elementId(p) = $id
         CREATE (u)-[:LIKED]->(p)`,
        { username: req.user.username, id }
      );
    }

    // Get updated like count
    const likeCount = await session.run(
      `MATCH (:User)-[:LIKED]->(p:Post)
       WHERE elementId(p) = $id 
       RETURN count(*) as count`,
      { id }
    );

    // Check if current user liked
    const likedByUser = await session.run(
      `MATCH (u:User {username: $username})-[r:LIKED]->(p:Post)
       WHERE elementId(p) = $id 
       RETURN count(r) as liked`,
      { username: req.user.username, id }
    );

    res.json({ 
      success: true,
      likes: likeCount.records[0].get('count').low,
      liked: likedByUser.records[0].get('liked').low > 0
    });
  } catch (err) {
    console.error('Like error:', err);
    res.status(500).json({ message: 'Error liking post.' });
  } finally {
    await session.close();
  }
});

// Fixed Comment Endpoint
app.post('/api/posts/:id/comment', authenticate, async (req, res) => {
  const { id } = req.params;
  const { text } = req.body;
  
  if (!text || text.trim().length === 0) {
    return res.status(400).json({ message: 'Comment text is required.' });
  }

  const session = driver.session();
  try {
    // First verify the post exists
    const postExists = await session.run(
      `MATCH (p:Post) WHERE elementId(p) = $id RETURN p`,
      { id }
    );

    if (postExists.records.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Create the comment
    const result = await session.run(
      `MATCH (u:User {username: $username}), (p:Post)
       WHERE elementId(p) = $id
       CREATE (c:Comment {
         text: $text,
         createdAt: datetime(),
         id: apoc.create.uuid()
       })
       CREATE (u)-[:CREATED]->(c)
       CREATE (c)-[:ON]->(p)
       RETURN c, u`,
      { 
        username: req.user.username,
        id,
        text: text.trim()
      }
    );

    const comment = result.records[0].get('c').properties;
    const user = result.records[0].get('u').properties;
    
    res.status(201).json({
      id: comment.id || comment.elementId,
      text: comment.text,
      createdAt: comment.createdAt,
      user: {
        username: user.username,
        avatar: user.avatar || 'default-avatar.png'
      }
    });
  } catch (err) {
    console.error('Comment error:', err);
    res.status(500).json({ 
      message: 'Error adding comment.',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  } finally {
    await session.close();
  }
});

app.get('/api/posts/feed', authenticate, async (req, res) => {
  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (p:Post)<-[:CREATED]-(u:User)
       OPTIONAL MATCH (p)<-[r:LIKED]-(:User)
       OPTIONAL MATCH (p)<-[:ON]-(c:Comment)<-[:CREATED]-(cu:User)
       WITH p, u, count(r) as likes, collect({
         id: elementId(c),
         text: c.text, 
         createdAt: c.createdAt, 
         user: {
           username: cu.username, 
           avatar: cu.avatar
         }
       }) as comments
       RETURN p, u.username as username, u.avatar as userAvatar, likes, comments
       ORDER BY p.createdAt DESC
       LIMIT 20`
    );

    const posts = result.records.map(record => {
      const post = record.get('p').properties;
      return {
        id: post.elementId,
        content: post.content,
        media: post.media,
        createdAt: post.createdAt,
        user: {
          username: record.get('username'),
          avatar: record.get('userAvatar') || 'default-avatar.png'
        },
        likes: record.get('likes').low,
        comments: record.get('comments') || []
      };
    });

    res.json(posts);
  } catch (err) {
    console.error('Feed error:', err);
    res.status(500).json({ message: 'Error fetching feed.' });
  } finally {
    await session.close();
  }
});

// Follow Routes
app.post('/api/users/:username/follow', authenticate, async (req, res) => {
  const { username } = req.params;
  const session = driver.session();

  try {
    const check = await session.run(
      `MATCH (u:User {username: $currentUser})-[r:FOLLOWS]->(t:User {username: $targetUser})
       RETURN r`,
      { currentUser: req.user.username, targetUser: username }
    );

    if (check.records.length > 0) {
      await session.run(
        `MATCH (u:User {username: $currentUser})-[r:FOLLOWS]->(t:User {username: $targetUser})
         DELETE r`,
        { currentUser: req.user.username, targetUser: username }
      );
      res.json({ success: true, following: false });
    } else {
      await session.run(
        `MATCH (u:User {username: $currentUser}), (t:User {username: $targetUser})
         CREATE (u)-[:FOLLOWS]->(t)`,
        { currentUser: req.user.username, targetUser: username }
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

app.get('/api/users/:username/following', authenticate, async (req, res) => {
  const { username } = req.params;
  const session = driver.session();

  try {
    const result = await session.run(
      `MATCH (u:User {username: $username})-[:FOLLOWS]->(f:User)
       RETURN f.username as username, f.avatar as avatar`,
      { username }
    );

    const following = result.records.map(record => ({
      username: record.get('username'),
      avatar: record.get('avatar') || 'default-avatar.png'
    }));

    res.json(following);
  } catch (err) {
    console.error('Following list error:', err);
    res.status(500).json({ message: 'Error fetching following list.' });
  } finally {
    await session.close();
  }
});

// Search Routes
app.get('/api/search/users', authenticate, async (req, res) => {
  const { username } = req.query;
  
  if (!username || username.trim().length < 2) {
    return res.status(400).json({ message: 'Search query must be at least 2 characters.' });
  }

  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (u:User)
       WHERE toLower(u.username) CONTAINS toLower($username)
       RETURN u.username as username, u.avatar as avatar
       LIMIT 10`,
      { username: username.trim() }
    );

    const users = result.records.map(record => ({
      username: record.get('username'),
      avatar: record.get('avatar') || 'default-avatar.png'
    }));

    res.json(users);
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ message: 'Error searching users.' });
  } finally {
    await session.close();
  }
});

app.get('/api/users/suggestions', authenticate, async (req, res) => {
  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (u:User)
       WHERE u.username <> $username
       RETURN u.username as username, u.avatar as avatar
       ORDER BY rand()
       LIMIT 5`,
      { username: req.user.username }
    );

    const suggestions = result.records.map(record => ({
      username: record.get('username'),
      avatar: record.get('avatar') || 'default-avatar.png'
    }));

    res.json(suggestions);
  } catch (err) {
    console.error('Suggestions error:', err);
    res.status(500).json({ message: 'Error fetching suggestions.' });
  } finally {
    await session.close();
  }
});

// Serve frontend files
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
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

// Server startup
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    driver.close();
    console.log('Server closed. Database connection terminated.');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    driver.close();
    console.log('Server closed. Database connection terminated.');
    process.exit(0);
  });
});