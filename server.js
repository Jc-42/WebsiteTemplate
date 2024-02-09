const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
 
const methodOverride = require('method-override')
const initializePassport = require('./passport-config')

const mysql = require('mysql'); 
const cors = require('cors');


app.set('view-engine', 'ejs')
app.use(express.urlencoded({extended : false}))
app.use(flash())
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, expires: 1000 * 60 * 120 } //session expire in 120 minutes
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

app.use((req, res, next) => {
  res.locals.error = req.flash('error');
  next();
});

app.use(cors({ origin: 'http://publicip' }));

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

//req.user.name

app.get('/', checkAuthenticated, (req, res) => {
  res.redirect('account')
});

app.get('/account', checkAuthenticated, (req, res) => {
  res.render('account.ejs', {name: req.user.name})
});
   
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
    
});

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs')
});

/*example of API
app.get('/api/alltimestockdata', (req, res) => {
  let sql = 'SELECT * FROM stock_all_time_price';
  let query = db.query(sql, (err, results) => {
      if (err) throw err; 
      res.send(results);
  });
});
*/

//get user data
app.get('/api/userdata', checkAuthenticated, (req, res) => {
  let sql = 'SELECT * FROM users WHERE email = ?';
  let email = req.user.email;

  let query = db.query(sql, [email], (err, results) => {
    if (err) throw err;
    res.send(results);
  })
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/account',
    failureRedirect: '/login',
    failureFlash: true
}));

app.post('/register', checkNotAuthenticated, async (req, res, next) => {
  try {
      let hashedPassword = await bcrypt.hash(req.body.password, 10);

      let name = req.body.name; //name attribute of input
      let username = req.body.username; //name attribute of input
      let email = req.body.email; //name attribute of input

      let selectQuery = 'SELECT * FROM users WHERE email = ?'

      db.query(selectQuery, [email], (err, result) => {
          if (err) {
              console.error('Error checking email:', err);
              req.flash('error', 'An error occurred');
              res.redirect('/register');
          } else if (result.length > 0) {
              req.flash('error', 'Email is already in use');
              res.redirect('/register');
          } else {
              selectQuery = 'SELECT * FROM users WHERE username = ?'

              db.query(selectQuery, [username], (err, result) => {
                if(err){
                  console.error('Error checking username:', err);
                  req.flash('error', 'An error occurred');
                  res.redirect('/register');
                } else if(result.length > 0) {
                  req.flash('error', 'Username is already in use');
                  res.redirect('/register');
                }
                else{
                  let insertQuery = 'INSERT INTO users (email, name, username, password_hash) VALUES (?, ?, ?, ?)';

                  db.query(insertQuery, [email, name, username, hashedPassword], (err, result) => {
                      if (err) {
                          console.error('Error creating user:', err);
                          req.flash('error', 'An error occurred');
                          res.redirect('/register');  
                      } else {
                          console.log('User created:', name);
                          res.redirect('/login');
                      }
                  });
                }
              });
              
          }
      });
  } catch (error) {
      console.error('Error:', error);
      req.flash('error', 'An error occurred');
      res.redirect('/register');
  }
});


app.delete('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/login');
  });
});
  


function getUserByEmail(email) {
  return new Promise((resolve, reject) => {
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
      if (err) {
        reject(err);
      } else {
        resolve(results[0]); //assuming that email is unique
      }
    });
  });
}
  
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next()
  }

  res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/')
  }
  next()
}
initializePassport(
  passport,
  getUserByEmail
)






app.listen(3000);