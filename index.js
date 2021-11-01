const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const SECRET = 'secret';

const hash = '$2a$10$2lmk2uvs2ttxd98YxRwEY.gB5DYg5sKnmyQks4v5Hd7M37WUZyay6';

app.use(express.json());

app.get('/test/:id', (req, res) => {
  res.send(req.params.id);
});

app.get('/compare/:pass', (req, res) => {
  const { params: { pass } } = req;
  // const { pass } = req.params;

  bcrypt.compare(pass, hash)
    .then(equal => {
      res.send(equal);
    })
    .catch(err => {
      res.status(500).send(err);
    });
});

app.post('/login', (req, res) => {
  const { body: { user, password }} = req;

  bcrypt.compare(password, hash)
    .then(equal => {
      if (equal) {
        return true
      }
      throw new Error('Forbidden');
    })
    .then(() => {
      const token = jwt.sign({ id: 45 }, SECRET, { expiresIn: 30 });

      res.send(token);
    })
    .catch(err => {
      res.status(403).send(err.message);
    });
});

const verifyTokenMiddleware = (req, res, next) => {
  if (req.header('Authorization') === undefined) return res.status(403).send('You need to have a valid token');
  const token = req.header('Authorization').replace('Bearer ', '');
  try {
    const data = jwt.verify(token, SECRET);
    req.tokenData = data;
    next();
  } catch (err) {
    const { message } = err;
    let errorMessage;
    console.log('error', err)
    if (message.includes('expired')) errorMessage = 'Token expired, request another one';
    if (message.includes('invalid')) errorMessage = 'Invalid token, request another one';
    res.status(403).send(errorMessage);
  }
}

app.get('/userinfo/:id', verifyTokenMiddleware, (req, res) => {
  const {tokenData} = req;
  res.send(tokenData);
});

app.get('/pets', verifyTokenMiddleware, (req, res) => {
  const {tokenData} = req;
  tokenData.pet = "Hello World!";
  res.send(tokenData);
})

app.get('/:pass', (req, res) => {
  const { params: { pass } } = req;
  // const { pass } = req.params;
  
  bcrypt.hash(pass, 10)
    .then(hash => res.send(hash))
    .catch(err => res.status(500).send(err));
});

app.listen(3001, () => {
  console.log('Listening on port 3001');
});