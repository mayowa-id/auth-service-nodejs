require('dotenv').config();
const mongoose = require('mongoose');

mongoose.connect("mongodb+srv://idowumayowa02:twilightworld@cluster0.cz8hg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((error) => console.error('Error connecting to MongoDB:', error));