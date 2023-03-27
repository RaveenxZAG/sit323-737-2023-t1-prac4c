const passport = require('passport');
const passportJWT = require('passport-jwt');
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const jwtSecret = 'your_jwt_secret_key';

const jwtOptions = {
  jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
  secretOrKey: jwtSecret
};

const jwtStrategy = new JWTStrategy(jwtOptions, (jwtPayload, done) => {
  if (jwtPayload.sub === 'user') {
    return done(null, true);
  } else {
    return done(null, false);
  }
});

passport.use(jwtStrategy);
