const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const base64url = require('base64url');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const RP_NAME = 'Your App Name';
const RP_ID = 'yubikeyfe.vercel.app'; // Replace with your actual domain
const ORIGIN = 'https://yubikeyfe.vercel.app'; // Replace with your frontend URL

app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
const mongoUri = 'mongodb+srv://gowtham:none@cluster0.jlft8pp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error: ', err));

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  credentials: [
    {
      credentialID: String,
      publicKey: String,
      counter: Number,
    },
  ],
  currentChallenge: String,
});

const User = mongoose.model('User', userSchema);

app.post('/register', async (req, res) => {
  const { email } = req.body;
  console.log('Register request received for email:', email);
  if (!email) {
    console.log('Email is required');
    return res.status(400).json({ error: 'Email is required' });
  }

  let user = await User.findOne({ email });
  if (!user) {
    user = new User({ email, credentials: [] });
  }
  console.log('User found or created:', user);

  const userIdBuffer = new TextEncoder().encode(email);
  const options = generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: userIdBuffer,
    userName: email,
    attestationType: 'direct',
  });

  user.currentChallenge = options.challenge;
  await user.save();
  console.log('Registration options generated and user updated:', options);

  return res.json(options);
});

app.post('/register/verify', async (req, res) => {
  const { email, attestation } = req.body;
  console.log('Register verify request received for email:', email);
  if (!email || !attestation) {
    console.log('Email and attestation are required');
    return res.status(400).json({ error: 'Email and attestation are required' });
  }

  const user = await User.findOne({ email });
  if (!user) {
    console.log('User not found');
    return res.status(400).json({ error: 'User not found' });
  }
  console.log('User found:', user);

  const expectedChallenge = user.currentChallenge;
  console.log('Expected challenge:', expectedChallenge);

  try {
    const { verified, registrationInfo } = await verifyRegistrationResponse({
      credential: attestation,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (verified) {
      user.credentials.push({
        credentialID: base64url.encode(registrationInfo.credentialID),
        publicKey: base64url.encode(registrationInfo.credentialPublicKey),
        counter: registrationInfo.counter,
      });
      await user.save();
      console.log('Registration successful and user updated:', user);
      return res.json({ message: 'Registration successful' });
    }

    console.log('Verification failed');
    return res.status(400).json({ error: 'Verification failed' });
  } catch (error) {
    console.log('Error during verification:', error.message);
    return res.status(400).json({ error: error.message });
  }
});

app.post('/authenticate', async (req, res) => {
  const { email } = req.body;
  console.log('Authenticate request received for email:', email);
  if (!email) {
    console.log('Email is required');
    return res.status(400).json({ error: 'Email is required' });
  }

  const user = await User.findOne({ email });
  if (!user || user.credentials.length === 0) {
    console.log('No registered credentials found for user');
    return res.status(400).json({ error: 'No registered credentials found for user' });
  }
  console.log('User found:', user);

  const options = generateAuthenticationOptions({
    allowCredentials: user.credentials.map(cred => ({
      id: base64url.toBuffer(cred.credentialID),
      type: 'public-key',
      transports: ['usb', 'ble', 'nfc', 'internal'],
    })),
    userVerification: 'preferred',
    rpID: RP_ID,
  });

  user.currentChallenge = options.challenge;
  await user.save();
  console.log('Authentication options generated and user updated:', options);

  return res.json(options);
});

app.post('/authenticate/verify', async (req, res) => {
  const { email, assertion } = req.body;
  console.log('Authenticate verify request received for email:', email);
  if (!email || !assertion) {
    console.log('Email and assertion are required');
    return res.status(400).json({ error: 'Email and assertion are required' });
  }

  const user = await User.findOne({ email });
  if (!user) {
    console.log('User not found');
    return res.status(400).json({ error: 'User not found' });
  }
  console.log('User found:', user);

  const expectedChallenge = user.currentChallenge;
  console.log('Expected challenge:', expectedChallenge);
  const credential = user.credentials.find(cred => cred.credentialID === base64url.encode(assertion.id));
  if (!credential) {
    console.log('Credential not found');
    return res.status(400).json({ error: 'Credential not found' });
  }
  console.log('Credential found:', credential);

  try {
    const { verified, authenticationInfo } = await verifyAuthenticationResponse({
      credential: assertion,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialPublicKey: base64url.toBuffer(credential.publicKey),
        credentialID: base64url.toBuffer(credential.credentialID),
        counter: credential.counter,
      },
    });

    if (verified) {
      credential.counter = authenticationInfo.newCounter;
      await user.save();
      console.log('Authentication successful and user updated:', user);
      return res.json({ message: 'Authentication successful' });
    }

    console.log('Verification failed');
    return res.status(400).json({ error: 'Verification failed' });
  } catch (error) {
    console.log('Error during verification:', error.message);
    return res.status(400).json({ error: error.message });
  }
});

app.listen(3001, () => {
  console.log('Server running on port 3001');
});
