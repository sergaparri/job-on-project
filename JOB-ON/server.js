const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();

// Essential middleware
app.use(cors());
app.use(express.json());

// Create a router for API routes
const apiRouter = express.Router();

// Add middleware to ensure JSON content type for all API routes
apiRouter.use((req, res, next) => {
    res.setHeader('Content-Type', 'application/json');
    next();
});

// Error handling middleware for API routes
apiRouter.use((err, req, res, next) => {
    console.error('API Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Mount API routes at /api BEFORE other middleware
app.use('/api', apiRouter);

// Then serve static files
app.use(express.static('public'));

// Then HTML routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/seeker-profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'seeker-profile.html'));
});

app.get('/employer-profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'employer-profile.html'));
});

app.get('/notifications.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'notifications.html'));
});

app.get('/post-job.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'post-job.html'));
});

// Catch-all route - this should be the LAST route
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'job_on'
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  console.log('Connected to MySQL database');
  
  // Create tables if they don't exist
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      first_name VARCHAR(50),
      last_name VARCHAR(50),
      email VARCHAR(100) UNIQUE,
      password VARCHAR(255),
      phone VARCHAR(20),
      user_type ENUM('job_seeker', 'employer'),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const createProfilesTable = `
    CREATE TABLE IF NOT EXISTS profiles (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      resume_url VARCHAR(255),
      company_name VARCHAR(100),
      company_description TEXT,
      location VARCHAR(100),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `;

  const createJobsTable = `
    CREATE TABLE IF NOT EXISTS jobs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      company_name VARCHAR(100),
      company_description TEXT,
      job_title VARCHAR(100),
      job_description TEXT,
      number_of_people INT,
      job_location VARCHAR(100),
      min_salary DECIMAL(12,2),
      max_salary DECIMAL(12,2),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `;

  const createPostsTable = `
    CREATE TABLE IF NOT EXISTS posts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      content TEXT,
      image_url VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `;

  const createInteractionsTable = `
    CREATE TABLE IF NOT EXISTS interactions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      post_id INT,
      user_id INT,
      type ENUM('like', 'comment', 'share'),
      comment_text TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (post_id) REFERENCES posts(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `;

  const createNotificationsTable = `
    CREATE TABLE IF NOT EXISTS notifications (
      id INT AUTO_INCREMENT PRIMARY KEY,
      employer_id INT,
      applicant_id INT,
      job_id INT,
      status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
      is_read BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (employer_id) REFERENCES users(id),
      FOREIGN KEY (applicant_id) REFERENCES users(id),
      FOREIGN KEY (job_id) REFERENCES jobs(id)
    )
  `;

  const createCommentsTable = `
    CREATE TABLE IF NOT EXISTS comments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      notification_id INT,
      user_id INT,
      parent_id INT NULL,
      content TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (notification_id) REFERENCES notifications(id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (parent_id) REFERENCES comments(id)
    )
  `;

  // Execute table creation queries in sequence
  db.query(createUsersTable, (err) => {
    if (err) {
      console.error('Error creating users table:', err);
      return;
    }
    console.log('Users table created successfully');

    db.query(createProfilesTable, (err) => {
      if (err) {
        console.error('Error creating profiles table:', err);
        return;
      }
      console.log('Profiles table created successfully');

      db.query(createJobsTable, (err) => {
        if (err) {
          console.error('Error creating jobs table:', err);
          return;
        }
        console.log('Jobs table created successfully');
      });

      db.query(createPostsTable, (err) => {
        if (err) {
          console.error('Error creating posts table:', err);
          return;
        }
        console.log('Posts table created successfully');

        db.query(createInteractionsTable, (err) => {
          if (err) {
            console.error('Error creating interactions table:', err);
            return;
          }
          console.log('Interactions table created successfully');

          db.query(createNotificationsTable, (err) => {
            if (err) {
              console.error('Error creating notifications table:', err);
              return;
            }
            console.log('Notifications table created successfully');

            db.query(createCommentsTable, (err) => {
              if (err) {
                console.error('Error creating comments table:', err);
                return;
              }
              console.log('Comments table created successfully');
            });
          });
        });
      });
    });
  });
});

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/');
    },
    filename: (req, file, cb) => {
        // Get file extension
        const ext = path.extname(file.originalname);
        // Create filename with timestamp and original extension
        cb(null, `resume-${Date.now()}${ext}`);
    }
});

const fileFilter = (req, file, cb) => {
    // Accept only pdf, doc, docx files
    const allowedTypes = ['.pdf', '.doc', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (allowedTypes.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only PDF, DOC, and DOCX files are allowed.'));
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication token is required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key', (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Token has expired' });
            }
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { first_name, last_name, email, password, phone, user_type, company_name, company_description } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    // Start a transaction
    db.beginTransaction(async (err) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }

      try {
        // Insert user
        const insertUserQuery = 'INSERT INTO users (first_name, last_name, email, password, phone, user_type) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(insertUserQuery, [first_name, last_name, email, hashedPassword, phone, user_type], (err, result) => {
          if (err) {
            return db.rollback(() => {
              res.status(500).json({ error: err.message });
            });
          }

          const userId = result.insertId;

          // Create profile based on user type
          const insertProfileQuery = user_type === 'employer' 
            ? 'INSERT INTO profiles (user_id, company_name, company_description) VALUES (?, ?, ?)'
            : 'INSERT INTO profiles (user_id, location) VALUES (?, ?)';
            
          const profileValues = user_type === 'employer' 
            ? [userId, company_name || null, company_description || null]
            : [userId, null];

          db.query(insertProfileQuery, profileValues, (err) => {
            if (err) {
              return db.rollback(() => {
                res.status(500).json({ error: err.message });
              });
            }

            // Commit transaction
            db.commit((err) => {
              if (err) {
                return db.rollback(() => {
                  res.status(500).json({ error: err.message });
                });
              }
              res.status(201).json({ message: 'User registered successfully' });
            });
          });
        });
      } catch (error) {
        db.rollback(() => {
          res.status(500).json({ error: error.message });
        });
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }

      if (results.length === 0) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const user = results[0];
      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const token = jwt.sign(
        { id: user.id, email: user.email, user_type: user.user_type },
        process.env.JWT_SECRET || 'your_jwt_secret_key'
      );

      res.json({ token, user_type: user.user_type });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Protected routes
app.post('/api/posts', authenticateToken, upload.single('image'), (req, res) => {
  const { content } = req.body;
  const image_url = req.file ? `/uploads/${req.file.filename}` : null;

  const query = 'INSERT INTO posts (user_id, content, image_url) VALUES (?, ?, ?)';
  db.query(query, [req.user.id, content, image_url], (err, result) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.status(201).json({ message: 'Post created successfully' });
  });
});

app.post('/api/interactions', authenticateToken, (req, res) => {
  const { post_id, type, comment_text } = req.body;

  const query = 'INSERT INTO interactions (post_id, user_id, type, comment_text) VALUES (?, ?, ?, ?)';
  db.query(query, [post_id, req.user.id, type, comment_text], (err, result) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.status(201).json({ message: 'Interaction recorded successfully' });
  });
});

// Profile endpoint
apiRouter.get('/profile', authenticateToken, (req, res) => {
    console.log('Profile request received for user:', req.user.id);
    
    if (!req.user || !req.user.id) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    const query = `
        SELECT 
            u.first_name, 
            u.last_name, 
            u.email, 
            u.phone,
            u.user_type,
            p.location,
            p.resume_url,
            p.company_name,
            p.company_description
        FROM users u 
        LEFT JOIN profiles p ON u.id = p.user_id 
        WHERE u.id = ?
    `;
    
    db.query(query, [req.user.id], (err, results) => {
        if (err) {
            console.error('Database error in profile endpoint:', err);
            return res.status(500).json({ error: 'Failed to fetch profile data' });
        }

        if (!results || results.length === 0) {
            console.error('No profile found for user:', req.user.id);
            return res.status(404).json({ error: 'Profile not found' });
        }

        const userData = results[0];
        
        // Return different data based on user type
        if (userData.user_type === 'employer') {
            return res.json({
                firstName: userData.first_name,
                lastName: userData.last_name,
                email: userData.email,
                phone: userData.phone || null,
                companyName: userData.company_name || null,
                companyDescription: userData.company_description || null,
                userType: userData.user_type
            });
        } else {
            return res.json({
                firstName: userData.first_name,
                lastName: userData.last_name,
                email: userData.email,
                phone: userData.phone || null,
                location: userData.location || null,
                resumeUrl: userData.resume_url || null,
                userType: userData.user_type
            });
        }
    });
});

// Resume upload endpoint
app.post('/api/upload-resume', authenticateToken, upload.single('resume'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const resumeUrl = `/uploads/${req.file.filename}`;

    // Update or insert resume URL in profiles table
    const query = `
        INSERT INTO profiles (user_id, resume_url)
        VALUES (?, ?)
        ON DUPLICATE KEY UPDATE resume_url = ?
    `;

    db.query(query, [req.user.id, resumeUrl, resumeUrl], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to update resume information' });
        }

        res.json({ 
            message: 'Resume uploaded successfully',
            resumeUrl: resumeUrl
        });
    });
});

// Delete resume endpoint
app.delete('/api/delete-resume', authenticateToken, (req, res) => {
    // First get the current resume URL
    const getResumeQuery = 'SELECT resume_url FROM profiles WHERE user_id = ?';
    
    db.query(getResumeQuery, [req.user.id], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to delete resume' });
        }

        if (results.length > 0 && results[0].resume_url) {
            const resumePath = path.join(__dirname, 'public', results[0].resume_url);
            
            // Delete the file if it exists
            if (fs.existsSync(resumePath)) {
                try {
                    fs.unlinkSync(resumePath);
                } catch (error) {
                    console.error('File deletion error:', error);
                }
            }

            // Update the database
            const updateQuery = 'UPDATE profiles SET resume_url = NULL WHERE user_id = ?';
            db.query(updateQuery, [req.user.id], (err, result) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Failed to update resume information' });
                }

                res.json({ message: 'Resume deleted successfully' });
            });
        } else {
            res.status(404).json({ error: 'No resume found' });
        }
    });
});

// Job posting endpoint
app.post('/api/jobs', authenticateToken, (req, res) => {
    const {
        companyName,
        companyDescription,
        jobTitle,
        jobDescription,
        numberOfPeople,
        jobLocation,
        salaryRange
    } = req.body;

    const query = `
        INSERT INTO jobs (
            user_id,
            company_name,
            company_description,
            job_title,
            job_description,
            number_of_people,
            job_location,
            min_salary,
            max_salary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
        query,
        [
            req.user.id,
            companyName,
            companyDescription,
            jobTitle,
            jobDescription,
            numberOfPeople,
            jobLocation,
            salaryRange.min,
            salaryRange.max
        ],
        (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to create job posting' });
            }

            res.status(201).json({
                message: 'Job posted successfully',
                jobId: result.insertId
            });
        }
    );
});

// API Routes
apiRouter.post('/jobs/:jobId/apply', authenticateToken, (req, res) => {
    const jobId = req.params.jobId;
    const applicantId = req.user.id;

    // First get the job details to get the employer ID
    const getJobQuery = 'SELECT user_id as employer_id FROM jobs WHERE id = ?';
    db.query(getJobQuery, [jobId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to process application' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Job not found' });
        }

        const employerId = results[0].employer_id;

        // Create notification
        const createNotificationQuery = `
            INSERT INTO notifications (employer_id, applicant_id, job_id)
            VALUES (?, ?, ?)
        `;

        db.query(createNotificationQuery, [employerId, applicantId, jobId], (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to create notification' });
            }

            res.status(201).json({ message: 'Application submitted successfully' });
        });
    });
});

// Get notifications for employer and job seeker
apiRouter.get('/notifications', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const userType = req.user.user_type;

    let query;
    if (userType === 'employer') {
        query = `
            SELECT 
                n.id,
                n.status,
                n.is_read,
                n.created_at as createdAt,
                j.job_title as jobTitle,
                u.first_name,
                u.last_name,
                u.email,
                p.resume_url
            FROM notifications n
            JOIN jobs j ON n.job_id = j.id
            JOIN users u ON n.applicant_id = u.id
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE n.employer_id = ?
            ORDER BY n.created_at DESC
        `;
    } else {
        query = `
            SELECT 
                n.id,
                n.status,
                n.is_read,
                n.created_at as createdAt,
                j.job_title as jobTitle,
                j.job_description,
                j.job_location,
                j.min_salary,
                j.max_salary,
                u.first_name as employer_first_name,
                u.last_name as employer_last_name,
                u.email as employer_email,
                p.company_name,
                p.company_description
            FROM notifications n
            JOIN jobs j ON n.job_id = j.id
            JOIN users u ON n.employer_id = u.id
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE n.applicant_id = ?
            ORDER BY n.created_at DESC
        `;
    }

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch notifications' });
        }

        const notifications = results.map(notification => {
            if (userType === 'employer') {
                return {
                    id: notification.id,
                    jobTitle: notification.jobTitle,
                    status: notification.status,
                    isRead: notification.is_read === 1,
                    createdAt: notification.createdAt,
                    applicant: {
                        name: `${notification.first_name} ${notification.last_name}`,
                        email: notification.email,
                        resumeUrl: notification.resume_url
                    }
                };
            } else {
                return {
                    id: notification.id,
                    jobTitle: notification.jobTitle,
                    jobDescription: notification.job_description,
                    jobLocation: notification.job_location,
                    salaryRange: {
                        min: notification.min_salary,
                        max: notification.max_salary
                    },
                    status: notification.status,
                    isRead: notification.is_read === 1,
                    createdAt: notification.createdAt,
                    employer: {
                        name: `${notification.employer_first_name} ${notification.employer_last_name}`,
                        email: notification.employer_email,
                        company: {
                            name: notification.company_name,
                            description: notification.company_description
                        }
                    }
                };
            }
        });

        res.json(notifications);
    });
});

// Update notification status
apiRouter.put('/notifications/:id/status', authenticateToken, (req, res) => {
    const { status } = req.body;
    const notificationId = req.params.id;

    if (!['accepted', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    const query = 'UPDATE notifications SET status = ? WHERE id = ? AND employer_id = ?';
    db.query(query, [status, notificationId, req.user.id], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to update status' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        res.json({ message: 'Status updated successfully' });
    });
});

// Mark notification as read
apiRouter.put('/notifications/:id/read', authenticateToken, (req, res) => {
    const notificationId = req.params.id;

    const query = 'UPDATE notifications SET is_read = true WHERE id = ? AND employer_id = ?';
    db.query(query, [notificationId, req.user.id], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to mark as read' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        res.json({ message: 'Marked as read' });
    });
});

// Update company information
apiRouter.post('/update-company', authenticateToken, (req, res) => {
    const { description } = req.body;

    const query = 'UPDATE profiles SET company_description = ? WHERE user_id = ?';
    db.query(query, [description, req.user.id], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to update company information' });
        }

        res.json({ message: 'Company information updated successfully' });
    });
});

// Update profile
apiRouter.post('/update-profile', authenticateToken, (req, res) => {
    const { firstName, lastName, phone, location } = req.body;

    db.beginTransaction(async (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to update profile' });
        }

        try {
            // Update user table
            await db.query(
                'UPDATE users SET first_name = ?, last_name = ?, phone = ? WHERE id = ?',
                [firstName, lastName, phone, req.user.id]
            );

            // Update or insert into profiles table
            await db.query(
                'INSERT INTO profiles (user_id, location) VALUES (?, ?) ON DUPLICATE KEY UPDATE location = ?',
                [req.user.id, location, location]
            );

            db.commit((err) => {
                if (err) {
                    return db.rollback(() => {
                        res.status(500).json({ error: 'Failed to update profile' });
                    });
                }

                res.json({
                    message: 'Profile updated successfully',
                    user: { firstName, lastName, phone, location }
                });
            });
        } catch (error) {
            db.rollback(() => {
                res.status(500).json({ error: 'Failed to update profile' });
            });
        }
    });
});

// Get jobs endpoint
apiRouter.get('/jobs', async (req, res) => {
    try {
        const { search, location, sort = 'latest' } = req.query;
        
        let query = `
            SELECT 
                j.*,
                u.first_name,
                u.last_name,
                u.email,
                p.company_name,
                p.company_description
            FROM jobs j
            JOIN users u ON j.user_id = u.id
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE 1=1
        `;
        
        const queryParams = [];
        
        // Add search filter
        if (search) {
            query += ` AND (
                j.job_title LIKE ? OR 
                j.job_description LIKE ? OR 
                p.company_name LIKE ?
            )`;
            const searchTerm = `%${search}%`;
            queryParams.push(searchTerm, searchTerm, searchTerm);
        }
        
        // Add location filter
        if (location) {
            query += ` AND j.job_location = ?`;
            queryParams.push(location);
        }
        
        // Add sorting
        switch (sort) {
            case 'salary_high':
                query += ` ORDER BY j.max_salary DESC`;
                break;
            case 'salary_low':
                query += ` ORDER BY j.min_salary ASC`;
                break;
            case 'oldest':
                query += ` ORDER BY j.created_at ASC`;
                break;
            case 'latest':
            default:
                query += ` ORDER BY j.created_at DESC`;
        }
        
        db.query(query, queryParams, (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to fetch jobs' });
            }
            
            const jobs = results.map(job => ({
                id: job.id,
                title: job.job_title,
                description: job.job_description,
                location: job.job_location,
                numberOfPeople: job.number_of_people,
                salaryRange: {
                    min: job.min_salary,
                    max: job.max_salary
                },
                company: {
                    name: job.company_name,
                    description: job.company_description
                },
                employer: {
                    name: `${job.first_name} ${job.last_name}`,
                    email: job.email
                },
                createdAt: job.created_at
            }));
            
            res.json(jobs);
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Failed to fetch jobs' });
    }
});

// Get single job endpoint
apiRouter.get('/jobs/:id', async (req, res) => {
    try {
        const jobId = req.params.id;
        
        const query = `
            SELECT 
                j.*,
                u.first_name,
                u.last_name,
                u.email,
                p.company_name,
                p.company_description
            FROM jobs j
            JOIN users u ON j.user_id = u.id
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE j.id = ?
        `;
        
        db.query(query, [jobId], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to fetch job details' });
            }
            
            if (results.length === 0) {
                return res.status(404).json({ error: 'Job not found' });
            }
            
            const job = results[0];
            res.json({
                id: job.id,
                title: job.job_title,
                description: job.job_description,
                location: job.job_location,
                numberOfPeople: job.number_of_people,
                salaryRange: {
                    min: job.min_salary,
                    max: job.max_salary
                },
                company: {
                    name: job.company_name,
                    description: job.company_description
                },
                employer: {
                    name: `${job.first_name} ${job.last_name}`,
                    email: job.email
                },
                createdAt: job.created_at
            });
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Failed to fetch job details' });
    }
});

// Get jobs posted by the employer
apiRouter.get('/my-jobs', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'employer') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const query = `
            SELECT 
                j.*,
                COUNT(n.id) as total_applications,
                COUNT(CASE WHEN n.status = 'pending' THEN 1 END) as pending_applications,
                COUNT(CASE WHEN n.status = 'accepted' THEN 1 END) as accepted_applications,
                COUNT(CASE WHEN n.status = 'rejected' THEN 1 END) as rejected_applications
            FROM jobs j
            LEFT JOIN notifications n ON j.id = n.job_id
            WHERE j.user_id = ?
            GROUP BY j.id
            ORDER BY j.created_at DESC
        `;
        
        db.query(query, [req.user.id], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to fetch jobs' });
            }
            
            const jobs = results.map(job => ({
                id: job.id,
                title: job.job_title,
                description: job.job_description,
                location: job.job_location,
                numberOfPeople: job.number_of_people,
                salaryRange: {
                    min: job.min_salary,
                    max: job.max_salary
                },
                applications: {
                    total: job.total_applications,
                    pending: job.pending_applications,
                    accepted: job.accepted_applications,
                    rejected: job.rejected_applications
                },
                createdAt: job.created_at
            }));
            
            res.json(jobs);
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Failed to fetch jobs' });
    }
});

// Add new API endpoints for comments
apiRouter.post('/notifications/:notificationId/comments', authenticateToken, (req, res) => {
    const { content, parentId } = req.body;
    const notificationId = req.params.notificationId;
    const userId = req.user.id;

    // Verify user has access to this notification
    const accessQuery = `
        SELECT * FROM notifications 
        WHERE id = ? AND (employer_id = ? OR applicant_id = ?)
    `;

    db.query(accessQuery, [notificationId, userId, userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to verify access' });
        }

        if (results.length === 0) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Insert the comment
        const insertQuery = `
            INSERT INTO comments (notification_id, user_id, parent_id, content)
            VALUES (?, ?, ?, ?)
        `;

        db.query(insertQuery, [notificationId, userId, parentId || null, content], (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to create comment' });
            }

            // Fetch the created comment with user info
            const getCommentQuery = `
                SELECT 
                    c.*,
                    u.first_name,
                    u.last_name,
                    u.user_type
                FROM comments c
                JOIN users u ON c.user_id = u.id
                WHERE c.id = ?
            `;

            db.query(getCommentQuery, [result.insertId], (err, comments) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Failed to fetch comment' });
                }

                const comment = comments[0];
                res.status(201).json({
                    id: comment.id,
                    content: comment.content,
                    createdAt: comment.created_at,
                    user: {
                        id: comment.user_id,
                        name: `${comment.first_name} ${comment.last_name}`,
                        userType: comment.user_type
                    },
                    parentId: comment.parent_id
                });
            });
        });
    });
});

apiRouter.get('/notifications/:notificationId/comments', authenticateToken, (req, res) => {
    const notificationId = req.params.notificationId;
    const userId = req.user.id;

    // Verify user has access to this notification
    const accessQuery = `
        SELECT * FROM notifications 
        WHERE id = ? AND (employer_id = ? OR applicant_id = ?)
    `;

    db.query(accessQuery, [notificationId, userId, userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to verify access' });
        }

        if (results.length === 0) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Fetch all comments for this notification
        const getCommentsQuery = `
            SELECT 
                c.*,
                u.first_name,
                u.last_name,
                u.user_type
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.notification_id = ?
            ORDER BY c.created_at ASC
        `;

        db.query(getCommentsQuery, [notificationId], (err, comments) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to fetch comments' });
            }

            const formattedComments = comments.map(comment => ({
                id: comment.id,
                content: comment.content,
                createdAt: comment.created_at,
                user: {
                    id: comment.user_id,
                    name: `${comment.first_name} ${comment.last_name}`,
                    userType: comment.user_type
                },
                parentId: comment.parent_id
            }));

            res.json(formattedComments);
        });
    });
});

// Global error handling middleware
app.use((err, req, res, next) => {
    console.error('Global Error:', err);
    if (req.path.startsWith('/api/')) {
        res.status(500).json({ error: 'Internal server error' });
    } else {
        res.status(500).send('Internal server error');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 