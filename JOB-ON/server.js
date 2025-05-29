const express = require('express');
const mysql = require('mysql2/promise');
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

// Serve uploaded resumes
app.use('/uploads/resumes', express.static(path.join(__dirname, 'uploads/resumes')));

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
app.get(/^\/(?!.*\.\w+$).*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const resumesDir = path.join(__dirname, 'public', 'uploads', 'resumes');
if (!fs.existsSync(resumesDir)) {
    fs.mkdirSync(resumesDir, { recursive: true });
}

// Update the database connection to use promise-based mysql2
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'job_on',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Optimize multer configuration for faster uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'public', 'uploads', 'resumes'));
    },
    filename: function (req, file, cb) {
        // Use a simpler filename format for faster processing
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + ext);
    }
});

// Optimize file filter
const fileFilter = (req, file, cb) => {
    const allowedTypes = ['.pdf', '.doc', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (allowedTypes.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only PDF, DOC, and DOCX files are allowed.'));
    }
};

// Configure multer with optimized settings
const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 1 // Only allow one file
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
    const connection = await pool.getConnection();
    try {
      // Insert user
      const insertUserQuery = 'INSERT INTO users (first_name, last_name, email, password, phone, user_type) VALUES (?, ?, ?, ?, ?, ?)';
      const [result] = await connection.execute(insertUserQuery, [first_name, last_name, email, hashedPassword, phone, user_type]);

      const userId = result.insertId;

      // Create profile based on user type
      const insertProfileQuery = user_type === 'employer' 
        ? 'INSERT INTO profiles (user_id, company_name, company_description) VALUES (?, ?, ?)'
        : 'INSERT INTO profiles (user_id, location) VALUES (?, ?)';
        
      const profileValues = user_type === 'employer' 
        ? [userId, company_name || null, company_description || null]
        : [userId, null];

      await connection.execute(insertProfileQuery, profileValues);

      // Commit transaction
      await connection.commit();
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      await connection.rollback();
      res.status(500).json({ error: error.message });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const connection = await pool.getConnection();
    const query = 'SELECT * FROM users WHERE email = ?';
    const [results] = await connection.execute(query, [email]);

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
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Protected routes
app.post('/api/posts', authenticateToken, upload.single('image'), (req, res) => {
  const { content } = req.body;
  const image_url = req.file ? `/uploads/${req.file.filename}` : null;

  const query = 'INSERT INTO posts (user_id, content, image_url) VALUES (?, ?, ?)';
  pool.getConnection().then(connection => connection.execute(query, [req.user.id, content, image_url])).then(([result]) => {
    res.status(201).json({ message: 'Post created successfully' });
  }).catch((err) => {
    res.status(500).json({ error: err.message });
  });
});

app.post('/api/interactions', authenticateToken, (req, res) => {
  const { post_id, type, comment_text } = req.body;

  const query = 'INSERT INTO interactions (post_id, user_id, type, comment_text) VALUES (?, ?, ?, ?)';
  pool.getConnection().then(connection => connection.execute(query, [post_id, req.user.id, type, comment_text])).then(([result]) => {
    res.status(201).json({ message: 'Interaction recorded successfully' });
  }).catch((err) => {
    res.status(500).json({ error: err.message });
  });
});

// Profile endpoint
apiRouter.get('/profile', authenticateToken, async (req, res) => {
    const connection = await pool.getConnection();
    try {
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
        
        const [results] = await connection.execute(query, [req.user.id]);

        if (!results || results.length === 0) {
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
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch profile data' });
    } finally {
        connection.release();
    }
});

// Optimize resume upload endpoint
app.post('/api/upload-resume', authenticateToken, upload.single('resume'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const connection = await pool.getConnection();
    try {
        // Start transaction
        await connection.beginTransaction();

        // First check if a profile exists
        const [profileCheck] = await connection.execute(
            'SELECT id, resume_url FROM profiles WHERE user_id = ?',
            [req.user.id]
        );

        const resumeUrl = '/uploads/resumes/' + req.file.filename;

        if (profileCheck.length === 0) {
            // Create new profile with resume
            const [result] = await connection.execute(
                'INSERT INTO profiles (user_id, resume_url) VALUES (?, ?)',
                [req.user.id, resumeUrl]
            );

            if (result.affectedRows === 0) {
                throw new Error('Failed to create profile with resume');
            }
        } else {
            // If there's an existing resume, delete it
            if (profileCheck[0].resume_url) {
                const oldResumePath = path.join(__dirname, 'public', profileCheck[0].resume_url);
                if (fs.existsSync(oldResumePath)) {
                    fs.unlinkSync(oldResumePath);
                }
            }

            // Update existing profile
            const [result] = await connection.execute(
                'UPDATE profiles SET resume_url = ? WHERE user_id = ?',
                [resumeUrl, req.user.id]
            );

            if (result.affectedRows === 0) {
                throw new Error('Failed to update profile with resume');
            }
        }

        // Verify the update/insert was successful
        const [verifyResult] = await connection.execute(
            'SELECT resume_url FROM profiles WHERE user_id = ?',
            [req.user.id]
        );

        if (verifyResult.length === 0 || verifyResult[0].resume_url !== resumeUrl) {
            throw new Error('Failed to verify resume upload');
        }

        await connection.commit();

        res.json({ 
            message: 'Resume uploaded successfully',
            resumeUrl: resumeUrl
        });

    } catch (error) {
        await connection.rollback();
        // Clean up the uploaded file if database operation fails
        if (req.file && req.file.path) {
            fs.unlink(req.file.path, () => {});
        }
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to process resume upload: ' + error.message });
    } finally {
        connection.release();
    }
});

// Delete resume endpoint
app.delete('/api/delete-resume', authenticateToken, async (req, res) => {
    try {
        // First get the current resume URL
        const connection = await pool.getConnection();
        const [results] = await connection.execute('SELECT resume_url FROM profiles WHERE user_id = ?', [req.user.id]);

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
            await connection.execute('UPDATE profiles SET resume_url = NULL WHERE user_id = ?', [req.user.id]);
            res.json({ message: 'Resume deleted successfully' });
        } else {
            res.status(404).json({ error: 'No resume found' });
        }
    } catch (error) {
        console.error('Delete resume error:', error);
        res.status(500).json({ error: 'Failed to delete resume' });
    }
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

    pool.getConnection().then(connection => connection.execute(query, [
        req.user.id,
        companyName,
        companyDescription,
        jobTitle,
        jobDescription,
        numberOfPeople,
        jobLocation,
        salaryRange.min,
        salaryRange.max
    ])).then(([result]) => {
        res.status(201).json({
            message: 'Job posted successfully',
            jobId: result.insertId
        });
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to create job posting' });
    });
});

// API Routes
apiRouter.post('/jobs/:jobId/apply', authenticateToken, (req, res) => {
    const jobId = req.params.jobId;
    const applicantId = req.user.id;

    // First get the job details to get the employer ID
    const getJobQuery = 'SELECT user_id as employer_id FROM jobs WHERE id = ?';
    pool.getConnection().then(connection => connection.execute(getJobQuery, [jobId])).then(([results]) => {
        if (results.length === 0) {
            return res.status(404).json({ error: 'Job not found' });
        }

        const employerId = results[0].employer_id;

        // Create notification
        const createNotificationQuery = `
            INSERT INTO notifications (employer_id, applicant_id, job_id)
            VALUES (?, ?, ?)
        `;

        pool.getConnection().then(connection => connection.execute(createNotificationQuery, [employerId, applicantId, jobId])).then(([result]) => {
            res.status(201).json({ message: 'Application submitted successfully' });
        }).catch((err) => {
            console.error('Database error:', err);
            res.status(500).json({ error: 'Failed to create notification' });
        });
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to process application' });
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

    pool.getConnection().then(connection => connection.execute(query, [userId])).then(([results]) => {
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
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    });
});

// Update notification status with user notification
apiRouter.put('/notifications/:id/status', authenticateToken, async (req, res) => {
    console.log('Updating notification status:', {
        notificationId: req.params.id,
        status: req.body.status,
        userId: req.user.id
    });

    const { status } = req.body;
    const notificationId = req.params.id;
    let connection;

    if (!['accepted', 'rejected'].includes(status)) {
        console.error('Invalid status provided:', status);
        return res.status(400).json({ error: 'Invalid status. Must be either "accepted" or "rejected".' });
    }

    try {
        // Get connection from pool
        connection = await pool.getConnection();
        
        // Start transaction
        await connection.beginTransaction();

        // First get the notification details including applicant info
        const getDetailsQuery = `
            SELECT 
                n.*,
                j.job_title,
                u.email as applicant_email,
                u.first_name as applicant_first_name,
                u.last_name as applicant_last_name,
                e.first_name as employer_first_name,
                e.last_name as employer_last_name,
                c.company_name
            FROM notifications n
            JOIN jobs j ON n.job_id = j.id
            JOIN users u ON n.applicant_id = u.id
            JOIN users e ON n.employer_id = e.id
            LEFT JOIN profiles c ON e.id = c.user_id
            WHERE n.id = ? AND n.employer_id = ?
        `;

        console.log('Fetching notification details...');
        
        const [detailsResults] = await connection.execute(getDetailsQuery, [notificationId, req.user.id]);

        if (detailsResults.length === 0) {
            console.error('Notification not found or unauthorized');
            return res.status(404).json({ error: 'Notification not found or you are not authorized to update it' });
        }

        const notificationDetails = detailsResults[0];
        console.log('Found notification:', notificationDetails);

        // Update the notification status
        const updateQuery = 'UPDATE notifications SET status = ? WHERE id = ? AND employer_id = ?';
        console.log('Updating notification status...');

        const [updateResult] = await connection.execute(updateQuery, [status, notificationId, req.user.id]);

        if (updateResult.affectedRows === 0) {
            console.error('No rows affected in status update');
            return res.status(404).json({ error: 'Failed to update notification status - no matching record found' });
        }

        // Create a system message in comments
        const systemMessage = status === 'rejected' 
            ? 'Your application has been rejected.'
            : 'Congratulations! Your application has been accepted.';

        const commentQuery = `
            INSERT INTO comments (
                notification_id, 
                user_id, 
                content, 
                is_system_message
            ) VALUES (?, ?, ?, ?)
        `;

        console.log('Creating system message with params:', {
            notificationId,
            userId: req.user.id,
            systemMessage,
            isSystemMessage: true
        });

        await connection.execute(commentQuery, [
            notificationId, 
            req.user.id, 
            systemMessage, 
            true
        ]);

        // Create user notification for the applicant
        const notificationTitle = status === 'rejected' 
            ? 'Application Rejected'
            : 'Application Accepted';
        
        const notificationMessage = status === 'rejected'
            ? `Your application for ${notificationDetails.job_title} at ${notificationDetails.company_name} has been rejected.`
            : `Congratulations! Your application for ${notificationDetails.job_title} at ${notificationDetails.company_name} has been accepted.`;

        const createUserNotification = `
            INSERT INTO user_notifications (
                user_id,
                title,
                message,
                type,
                related_id
            ) VALUES (?, ?, ?, 'application_status', ?)
        `;

        console.log('Creating user notification...');

        await connection.execute(createUserNotification, [
            notificationDetails.applicant_id,
            notificationTitle,
            notificationMessage,
            notificationId
        ]);

        // Commit the transaction
        console.log('Committing transaction...');
        await connection.commit();

        console.log('Successfully updated notification status');
        // Send response
        res.json({ 
            message: 'Status updated successfully',
            notification: {
                id: notificationId,
                status,
                jobTitle: notificationDetails.job_title,
                applicant: {
                    name: `${notificationDetails.applicant_first_name} ${notificationDetails.applicant_last_name}`,
                    email: notificationDetails.applicant_email
                },
                employer: {
                    name: `${notificationDetails.employer_first_name} ${notificationDetails.employer_last_name}`,
                    company: notificationDetails.company_name
                }
            }
        });
    } catch (error) {
        console.error('Unexpected error:', error);
        if (connection) {
            await connection.rollback();
        }
        res.status(500).json({ error: 'An unexpected error occurred' });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Mark notification as read
apiRouter.put('/notifications/:id/read', authenticateToken, (req, res) => {
    const notificationId = req.params.id;

    const query = 'UPDATE notifications SET is_read = true WHERE id = ? AND employer_id = ?';
    pool.getConnection().then(connection => connection.execute(query, [notificationId, req.user.id])).then(([result]) => {
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        res.json({ message: 'Marked as read' });
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to mark as read' });
    });
});

// Update company information
apiRouter.post('/update-company', authenticateToken, (req, res) => {
    const { description } = req.body;

    const query = 'UPDATE profiles SET company_description = ? WHERE user_id = ?';
    pool.getConnection().then(connection => connection.execute(query, [description, req.user.id])).then(([result]) => {
        res.json({ message: 'Company information updated successfully' });
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to update company information' });
    });
});

// Update profile
apiRouter.post('/update-profile', authenticateToken, (req, res) => {
    const { firstName, lastName, phone, location } = req.body;

    pool.getConnection().then(connection => connection.beginTransaction()).then(async connection => {
        try {
            // Update user table
            await connection.execute(
                'UPDATE users SET first_name = ?, last_name = ?, phone = ? WHERE id = ?',
                [firstName, lastName, phone, req.user.id]
            );

            // Update or insert into profiles table
            await connection.execute(
                'INSERT INTO profiles (user_id, location) VALUES (?, ?) ON DUPLICATE KEY UPDATE location = ?',
                [req.user.id, location, location]
            );

            await connection.commit();
            res.json({
                message: 'Profile updated successfully',
                user: { firstName, lastName, phone, location }
            });
        } catch (error) {
            await connection.rollback();
            res.status(500).json({ error: 'Failed to update profile' });
        }
    }).catch((err) => {
        res.status(500).json({ error: 'Failed to update profile' });
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
        
        const connection = await pool.getConnection();
        const [results] = await connection.execute(query, queryParams);
        
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
        
        const connection = await pool.getConnection();
        const [results] = await connection.execute(query, [jobId]);
        
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
        
        const connection = await pool.getConnection();
        const [results] = await connection.execute(query, [req.user.id]);
        
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
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Failed to fetch jobs' });
    }
});

// Get comments for a notification
apiRouter.get('/notifications/:notificationId/comments', authenticateToken, async (req, res) => {
    const notificationId = req.params.notificationId;
    const userId = req.user.id;
    let connection;

    try {
        connection = await pool.getConnection();

        // Verify user has access to this notification
        const accessQuery = `
            SELECT * FROM notifications 
            WHERE id = ? AND (employer_id = ? OR applicant_id = ?)
        `;

        const [accessResults] = await connection.execute(accessQuery, [notificationId, userId, userId]);

        if (accessResults.length === 0) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Fetch all comments for this notification with user info
        const getCommentsQuery = `
            SELECT 
                c.*,
                u.first_name,
                u.last_name,
                u.user_type,
                u.id as user_id
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.notification_id = ?
            ORDER BY c.created_at ASC
        `;

        const [comments] = await connection.execute(getCommentsQuery, [notificationId]);

        const formattedComments = comments.map(comment => ({
            id: comment.id,
            content: comment.content,
            createdAt: comment.created_at,
            isSystemMessage: comment.is_system_message === 1,
            user: {
                id: comment.user_id,
                name: `${comment.first_name} ${comment.last_name}`,
                userType: comment.user_type
            },
            parentId: comment.parent_id
        }));

        res.json(formattedComments);

    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: 'Failed to load comments' });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Add comment endpoint
apiRouter.post('/notifications/:notificationId/comments', authenticateToken, async (req, res) => {
    const { content, parentId } = req.body;
    const notificationId = req.params.notificationId;
    const userId = req.user.id;
    let connection;

    try {
        connection = await pool.getConnection();

        // Verify user has access to this notification
        const accessQuery = `
            SELECT * FROM notifications 
            WHERE id = ? AND (employer_id = ? OR applicant_id = ?)
        `;

        const [accessResults] = await connection.execute(accessQuery, [notificationId, userId, userId]);

        if (accessResults.length === 0) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Insert the comment
        const insertQuery = `
            INSERT INTO comments (notification_id, user_id, parent_id, content, is_system_message)
            VALUES (?, ?, ?, ?, false)
        `;

        const [result] = await connection.execute(insertQuery, [
            notificationId, 
            userId, 
            parentId || null, 
            content
        ]);

        // Fetch the created comment with user info
        const getCommentQuery = `
            SELECT 
                c.*,
                u.first_name,
                u.last_name,
                u.user_type,
                u.id as user_id
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.id = ?
        `;

        const [comments] = await connection.execute(getCommentQuery, [result.insertId]);
        const comment = comments[0];

        res.status(201).json({
            id: comment.id,
            content: comment.content,
            createdAt: comment.created_at,
            isSystemMessage: comment.is_system_message === 1,
            user: {
                id: comment.user_id,
                name: `${comment.first_name} ${comment.last_name}`,
                userType: comment.user_type
            },
            parentId: comment.parent_id
        });

    } catch (error) {
        console.error('Error creating comment:', error);
        res.status(500).json({ error: 'Failed to create comment' });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get user notifications
apiRouter.get('/user-notifications', authenticateToken, (req, res) => {
    const query = `
        SELECT * FROM user_notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
    `;

    pool.getConnection().then(connection => connection.execute(query, [req.user.id])).then(([results]) => {
        res.json(results);
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    });
});

// Mark user notification as read
apiRouter.put('/user-notifications/:id/read', authenticateToken, (req, res) => {
    const query = 'UPDATE user_notifications SET is_read = true WHERE id = ? AND user_id = ?';
    
    pool.getConnection().then(connection => connection.execute(query, [req.params.id, req.user.id])).then(([result]) => {
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        res.json({ message: 'Notification marked as read' });
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to update notification' });
    });
});

// Delete a notification by ID (and its comments)
apiRouter.delete('/notifications/:id', authenticateToken, (req, res) => {
    const notificationId = req.params.id;
    const userId = req.user.id;
    const userType = req.user.user_type;

    // Only employer or applicant involved can delete
    const accessQuery = `
        SELECT * FROM notifications 
        WHERE id = ? AND (employer_id = ? OR applicant_id = ?)
    `;
    pool.getConnection().then(connection => connection.execute(accessQuery, [notificationId, userId, userId])).then(([results]) => {
        if (results.length === 0) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Delete notification (comments will cascade if FK is set)
        connection.execute('DELETE FROM notifications WHERE id = ?', [notificationId]).then(() => {
            res.json({ message: 'Notification deleted successfully' });
        }).catch((err) => {
            console.error('Database error:', err);
            res.status(500).json({ error: 'Failed to delete notification' });
        });
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to verify access' });
    });
});

// Delete a comment by ID
apiRouter.delete('/notifications/:notificationId/comments/:commentId', authenticateToken, (req, res) => {
    const { notificationId, commentId } = req.params;
    const userId = req.user.id;

    // Only comment owner or system/admin can delete
    const accessQuery = `
        SELECT * FROM comments 
        WHERE id = ? AND notification_id = ? AND user_id = ?
    `;
    pool.getConnection().then(connection => connection.execute(accessQuery, [commentId, notificationId, userId])).then(([results]) => {
        if (results.length === 0) {
            return res.status(403).json({ error: 'Access denied' });
        }

        connection.execute('DELETE FROM comments WHERE id = ?', [commentId]).then(() => {
            res.json({ message: 'Comment deleted successfully' });
        }).catch((err) => {
            console.error('Database error:', err);
            res.status(500).json({ error: 'Failed to delete comment' });
        });
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to verify access' });
    });
});

// Delete account endpoint
apiRouter.delete('/settings/delete-account', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();

        // Get user's resume URL before deletion
        const [profileResults] = await connection.execute(
            'SELECT resume_url FROM profiles WHERE user_id = ?',
            [userId]
        );

        // Delete user's resume file if it exists
        if (profileResults.length > 0 && profileResults[0].resume_url) {
            const resumePath = path.join(__dirname, 'public', profileResults[0].resume_url);
            if (fs.existsSync(resumePath)) {
                fs.unlinkSync(resumePath);
            }
        }

        // Delete from all related tables in the correct order
        const deleteQueries = [
            ['DELETE FROM comments WHERE user_id = ?', [userId]],
            ['DELETE FROM notifications WHERE employer_id = ? OR applicant_id = ?', [userId, userId]],
            ['DELETE FROM user_notifications WHERE user_id = ?', [userId]],
            ['DELETE FROM interactions WHERE user_id = ?', [userId]],
            ['DELETE FROM posts WHERE user_id = ?', [userId]],
            ['DELETE FROM jobs WHERE user_id = ?', [userId]],
            ['DELETE FROM profiles WHERE user_id = ?', [userId]],
            ['DELETE FROM users WHERE id = ?', [userId]]
        ];

        // Execute all delete queries
        for (const [query, params] of deleteQueries) {
            await connection.execute(query, params);
        }

        await connection.commit();
        res.json({ message: 'Account deleted successfully' });

    } catch (error) {
        await connection.rollback();
        console.error('Error deleting account:', error);
        res.status(500).json({ error: 'Failed to delete account. Please try again.' });
    } finally {
        connection.release();
    }
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

// Example for Express.js
app.delete('/api/user-notifications/:id', async (req, res) => {
    // Your logic to delete the notification by ID
});

apiRouter.delete('/user-notifications/:id', authenticateToken, (req, res) => {
    const notifId = req.params.id;
    const userId = req.user.id;
    pool.getConnection().then(connection => connection.execute(
        'DELETE FROM user_notifications WHERE id = ? AND user_id = ?',
        [notifId, userId]
    )).then(([result]) => {
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }
        res.json({ message: 'Notification deleted successfully' });
    }).catch((err) => {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Failed to delete notification' });
    });
});

// Update employer profile
apiRouter.post('/update-employer-profile', authenticateToken, async (req, res) => {
    const { firstName, lastName, phone, companyName, companyDescription } = req.body;
    let connection;

    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        // Update user table
        const [userResult] = await connection.execute(
            'UPDATE users SET first_name = ?, last_name = ?, phone = ? WHERE id = ?',
            [firstName, lastName, phone, req.user.id]
        );

        if (userResult.affectedRows === 0) {
            throw new Error('Failed to update user information');
        }

        // Update or insert into profiles table
        const [profileResult] = await connection.execute(
            `INSERT INTO profiles (user_id, company_name, company_description) 
             VALUES (?, ?, ?) 
             ON DUPLICATE KEY UPDATE 
             company_name = VALUES(company_name),
             company_description = VALUES(company_description)`,
            [req.user.id, companyName, companyDescription]
        );

        await connection.commit();

        res.json({
            message: 'Profile updated successfully',
            user: {
                firstName,
                lastName,
                phone,
                companyName,
                companyDescription
            }
        });

    } catch (error) {
        if (connection) {
            await connection.rollback();
        }
        console.error('Error updating employer profile:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});