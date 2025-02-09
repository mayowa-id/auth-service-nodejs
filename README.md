# auth-service-nodejs
Authentication and authorization service built with Node.js, Express, and MongoDB. 

# Overview
This is a robust authentication and authorization service built with Node.js, Express, and MongoDB. It supports traditional username-password authentication, OAuth2 login (Google & GitHub), JWT-based authentication, refresh tokens, and various security enhancements such as rate limiting and token blacklisting.

# Features
# Authentication & Authorization
- User Registration with secure password hashing
- User Login with JWT authentication
- OAuth2 Login (Google & GitHub)
- Role-based access control

# Security Enhancements
- Rate Limiting (Redis-based)
- Input Validation & Sanitization
- Secure HTTP Headers (Helmet)
- Strong Password Hashing (bcrypt)
- Token Blacklisting on Logout

# API Documentation
- Fully documented using Swagger UI

# Technologies Used
- Backend: Node.js, Express.js
- Database: MongoDB (Mongoose ODM)
- Authentication: JSON Web Tokens (JWT), Passport.js
- OAuth2 Providers: Google, GitHub
- Security: bcrypt, Helmet.js, Rate Limiting (Redis)
- API Documentation: Swagger UI
- Testing: Postman, Jest (optional)

# Installation & Setup
# Prerequisites
- Node.js (v16+ recommended)
- MongoDB
- Redis (for rate limiting & token blacklisting)
- Google & GitHub OAuth credentials

# Clone the Repository
```sh
git clone https://github.com/yourusername/auth-service.git
cd auth-service
```

# Install Dependencies
```sh
npm install
```

# Configure Environment Variables
Create a `.env` file in the root directory and add the following:
```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
REFRESH_SECRET=your_refresh_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
REDIS_HOST=localhost
REDIS_PORT=6379
```

# Start the Server
```sh
npm start
```

# API Endpoints
# Authentication Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Authenticate user and return JWT |
| POST | `/auth/logout` | Log out and invalidate refresh token |
| POST | `/auth/refresh-token` | Refresh access token using a valid refresh token |
| GET  | `/auth/profile` | Retrieve user profile (protected) |

# OAuth2 Routes
The following is the format 
Method | Endpoint | Description |

| GET | `/auth/google` | Initiate Google OAuth login |
| GET | `/auth/google/callback` | Google OAuth callback |
| GET | `/auth/github` | Initiate GitHub OAuth login |
| GET | `/auth/github/callback` | GitHub OAuth callback |

---
Contributions are welcome! If you have suggestions, feel free to open an issue or submit a pull request.


