const express = require('express');
const winston = require('winston');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');


const app = express();
const port = 3000;

// JWT secret key
const secretKey = 'mySecretKey';

// Middleware to generate JWT token
function generateToken(req, res, next) {
  const user = { username: 'myUsername', role: 'admin' };
  const token = jwt.sign(user, secretKey, { expiresIn: '1h' });
  req.token = token;
  next();
}



const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'calculator-microservice' },
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    }),
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error'
    }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secretKey
},
(jwtPayload, done) => {
  // Check if the user is authorized
  if (jwtPayload.role !== 'admin') {
    return done(null, false);
  }
  // If the user is authorized, return the user object
  return done(null, jwtPayload);
}
));

app.get('/add', passport.authenticate('jwt', { session: false }), (req, res) => {
  const num1 = parseFloat(req.query.num1);
  const num2 = parseFloat(req.query.num2);

  if (isNaN(num1) || isNaN(num2)) {
    logger.error('Invalid input');
    return res.status(400).json({ error: 'Invalid input' });
  }

  const result = num1 + num2;

  logger.log({
    level: 'info',
    message: `New addition operation requested: ${num1} + ${num2} = ${result}`
  });

  res.json({ result });
});

app.get('/subtract', passport.authenticate('jwt', { session: false }), (req, res) => {
  const num1 = parseFloat(req.query.num1);
  const num2 = parseFloat(req.query.num2);

  if (isNaN(num1) || isNaN(num2)) {
    logger.error('Invalid input');
    return res.status(400).json({ error: 'Invalid input' });
  }

  const result = num1 - num2;

  logger.log({
    level: 'info',
    message: `New subtraction operation requested: ${num1} - ${num2} = ${result}`
  });

  res.json({ result });
});

app.get('/divide', passport.authenticate('jwt', { session: false }), (req, res) => {
  const num1 = parseFloat(req.query.num1);
  const num2 = parseFloat(req.query.num2);

  if (isNaN(num1) || isNaN(num2)) {
    logger.error('Invalid input');
    return res.status(400).json({ error: 'Invalid input' });
  }

  const result = num1 / num2;

  logger.log({
    level: 'info',
    message: `New divition operation requested: ${num1} / ${num2} = ${result}`
  });

  res.json({ result });
});

app.get('/multiply', passport.authenticate('jwt', { session: false }), (req, res) => {
  const num1 = parseFloat(req.query.num1);
  const num2 = parseFloat(req.query.num2);

  if (isNaN(num1) || isNaN(num2)) {
    logger.error('Invalid input');
    return res.status(400).json({ error: 'Invalid input' });
  }

  const result = num1 * num2;

  logger.log({
    level: 'info',
    message: `New multiplication operation requested: ${num1} * ${num2} = ${result}`
  });

  res.json({ result });
});

app.get('/generateToken', generateToken, (req, res) => {
  res.json({ token: req.token });
});

app.listen(port, () => {
  console.log(`Calculator microservice listening at http://localhost:${port}`);
});
