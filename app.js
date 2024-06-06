const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const cors = require('cors')
const authRoutes = require('./routes/auth');

const app = express();
app.use(cors())
mongoose.connect('mongodb+srv://gowtham:bbvK5vU33zIDXAtY@cluster0.jlft8pp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', { useNewUrlParser: true, useUnifiedTopology: true });

app.use(bodyParser.json());
app.use(session({
    secret: 'your-secret-key', 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true } // Set secure to true if using HTTPS
}));

app.use('/auth', authRoutes);

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
