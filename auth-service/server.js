const Joi = require('joi');
const helmet = require('helmet');
const cors = require('cors');
const express = require('express');
const dbConfig = require('./config/database');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');
const passport = require('./config/passport');
const session = require('express-session');
const setupSwagger = require('./swaggerConfig');

const app = express();
setupSwagger(app);

app.use(helmet());
app.use(cors());
app.use(express.urlencoded({extended: true}));
app.use(express.json());

const port = process.env.PORT || 3000;

app.use('/auth', authRoutes);

app.get('/health', (req, res) => {
    const healthCheck = {
        uptime: process.uptime(),  
        message: 'OK',
        timestamp: Date.now()
    };
    try {
        res.send(healthCheck);
    } catch(error) {
        healthCheck.message = error;
        res.status(503).send();  
    }
});

async function connectDB() {
    try {
        await mongoose.connect("process.env.MONGO_URI", {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log("Database connected successfully.");
    } catch (error) {
        console.error("Database connection failed:", error);
    }
}
connectDB();

app.use(session({secret: process.env.JWT_SECRET, resave: false, saveUninitialized: false}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/auth',authRoutes);

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

module.exports = app;


