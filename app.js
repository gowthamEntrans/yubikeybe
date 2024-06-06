const express = require('express');
const u2f = require('u2f');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const APP_ID = 'https://yubikeyfe.vercel.app'; // Your frontend URL

app.use(cors());
app.use(bodyParser.json());

// In-memory user store (replace with a database in production)
const users = {};

app.post('/register', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const registrationRequest = u2f.request(APP_ID);
  users[email] = { registrationRequest, keys: [] };
  return res.json(registrationRequest);
});

app.post('/register/verify', (req, res) => {
  const { email, registrationResponse } = req.body;
  if (!email || !registrationResponse) {
    return res.status(400).json({ error: 'Email and registration response are required' });
  }

  const user = users[email];
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  const result = u2f.checkRegistration(user.registrationRequest, registrationResponse);
  if (result.successful) {
    user.keys.push({
      publicKey: result.publicKey,
      keyHandle: result.keyHandle,
    });
    return res.json({ message: 'Registration successful' });
  }

  return res.status(400).json({ error: result.errorMessage });
});

app.post('/authenticate', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const user = users[email];
  if (!user || user.keys.length === 0) {
    return res.status(400).json({ error: 'No registered keys found for user' });
  }

  const keyHandles = user.keys.map(key => key.keyHandle);
  const authRequest = u2f.request(APP_ID, keyHandles);
  users[email].authRequest = authRequest;
  return res.json(authRequest);
});

app.post('/authenticate/verify', (req, res) => {
  const { email, authResponse } = req.body;
  if (!email || !authResponse) {
    return res.status(400).json({ error: 'Email and authentication response are required' });
  }

  const user = users[email];
  if (!user || !user.authRequest) {
    return res.status(400).json({ error: 'Authentication request not found' });
  }

  const key = user.keys.find(key => key.keyHandle === authResponse.keyHandle);
  if (!key) {
    return res.status(400).json({ error: 'Key handle not found' });
  }

  const result = u2f.checkSignature(user.authRequest, authResponse, key.publicKey);
  if (result.successful) {
    return res.json({ message: 'Authentication successful' });
  }

  return res.status(400).json({ error: result.errorMessage });
});

app.listen(3001, () => {
  console.log('Server running on port 3001');
});
