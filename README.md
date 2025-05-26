# JOB-ON - Job Posting Platform

A modern job posting platform that connects job seekers with employers. Built with HTML, CSS, JavaScript, and MySQL.

## Features

### For Job Seekers
- Create and manage professional profile
- Upload and manage resume
- View job postings from employers
- Like and share job posts
- Interact with job posts through comments

### For Employers
- Create and manage company profile
- Post job opportunities
- Add images to job posts
- Track engagement on posts
- Manage job listings

## Prerequisites

- Node.js (v14 or higher)
- MySQL (v8 or higher)
- Modern web browser

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/job-on.git
cd job-on
```

2. Install dependencies:
```bash
npm install
```

3. Create a MySQL database:
```sql
CREATE DATABASE job_on;
```

4. Configure environment variables:
Create a `.env` file in the root directory with the following content:
```
DB_HOST=localhost
DB_USER=your_mysql_username
DB_PASSWORD=your_mysql_password
DB_NAME=job_on
JWT_SECRET=your_jwt_secret_key
PORT=3000
```

5. Create the `uploads` directory:
```bash
mkdir -p public/uploads
```

6. Start the server:
```bash
npm start
```

The application will be available at `http://localhost:3000`

## Project Structure

```
job-on/
├── public/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── auth.js
│   ├── images/
│   ├── uploads/
│   ├── index.html
│   ├── seeker-profile.html
│   └── employer-profile.html
├── server.js
├── package.json
└── README.md
```

## API Endpoints

### Authentication
- POST `/api/register` - Register new user
- POST `/api/login` - User login

### Profile Management
- GET `/api/profile` - Get user profile
- POST `/api/upload-resume` - Upload resume (job seekers)
- POST `/api/update-company` - Update company info (employers)

### Posts
- GET `/api/posts` - Get all job posts
- POST `/api/posts` - Create new job post
- DELETE `/api/posts/:id` - Delete job post
- GET `/api/company-posts` - Get company's job posts

### Interactions
- POST `/api/interactions` - Like/comment on post

## Security Features

- JWT-based authentication
- Password hashing with bcrypt
- Protected file uploads
- Input validation and sanitization

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
