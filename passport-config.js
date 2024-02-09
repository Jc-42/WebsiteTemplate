const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt');
const e = require('express');

function initialize(passport, getUserByEmail) {
  const authenticateUser = async (email, password, done) => {
    let user;
    try {
      user = await getUserByEmail(email);
    } catch (err) {
      return done(err);
    }
    if (user == null) {
      return done(null, false, { message: 'Incorrect username or password' })
    }

    try {
        bcrypt.compare(password, user.password_hash, function(err, result) {
          if(result == true){
            return done(null, user)
          }
          else{
            return done(null, false, { message: 'Incorrect username or password' })
          }
      });
      
    } catch (e) {
      return done(e)
    }
  }

  passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
  passport.serializeUser((user, done) => {
    done(null, user.email);
  });
  passport.deserializeUser((email, done) => {
    getUserByEmail(email).then(user => {
      done(null, user);
    }).catch(err => {
      done(err);
    });
  });
}

module.exports = initialize