require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive({
  connectionString: CONNECTION_STRING,
  ssl: {
    rejectUnauthorized:false
  }
}).then(db => {
  app.set('db', db);
});

app.post('/auth/signup', async (req, res) => {
  let { email, password } = req.body;
  let db = req.app.get('db')
  let [userFound] = await db.check_user_exists([email]);
  if (userFound) {
    return res.status(200).send('Email already exists')
  }
  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);
  let [createdUser] = await db.create_customer([email, hash])
  req.session.user = { id: createdUser.id, email: createdUser.email }
  res.status(200).send(req.session.user)
});

app.post('/auth/login', async (req, res) => {
  let db = req.app.get('db')
  let { email, password } = req.body;
  let [userFound] = await db.check_user_exists(email)
  if (!userFound) {
    return res.status(200).send('Incorrect email. Please try again.');
  }
  let authenticated = bcrypt.compareSync(password, userFound.user_password)
  if (authenticated) {
    req.session.user = { 
      id: userFound.id, 
      email: userFound.email }
    res.status(200).send(req.session.user)
  } else {
    return res.status(401).send('Incorrect email/password')
  }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.sendStatus(200);
});



app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
