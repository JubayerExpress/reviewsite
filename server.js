const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// Create Express app
const app = express();

// MongoDB connection
mongoose.connect('mongodb://localhost/book_review', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String
});

const User = mongoose.model('User', UserSchema);

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Passport Config
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
  User.findOne({ email: email }).then(user => {
    if (!user) {
      return done(null, false, { message: 'No user with that email' });
    }
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) throw err;
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Password incorrect' });
      }
    });
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

// Routes

// Sign Up Route
app.post('/signup', (req, res) => {
  const { username, email, password } = req.body;

  User.findOne({ email: email }).then(user => {
    if (user) {
      req.flash('error', 'Email already exists');
      res.redirect('/signup.html');
    } else {
      const newUser = new User({ username, email, password });
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser.save().then(() => {
            req.flash('success', 'You are registered and can log in');
            res.redirect('/login.html');
          }).catch(err => console.log(err));
        });
      });
    }
  });
});

// Login Route
app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard.html',
  failureRedirect: '/login.html',
  failureFlash: true
}));

// Protected Route
app.get('/dashboard.html', (req, res) => {
  if (req.isAuthenticated()) {
    res.send('Welcome to the dashboard');
  } else {
    res.redirect('/login.html');
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
