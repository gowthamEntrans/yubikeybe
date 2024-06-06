const express = require('express');
const u2f = require('u2f');
const User = require('../models/User');
const router = express.Router();

router.post('/registerRequest', async (req, res) => {
    try {
        const { username } = req.body;
        let user = await User.findOne({ username });
        if (!user) {
            user = new User({ username, devices: [] });
            await user.save();
        }
        const registerRequest = u2f.request('https://yubikeybe.onrender.com');
        req.session.registerRequest = registerRequest;
        res.json(registerRequest);
    } catch (error) {
        console.error('Error in registerRequest:', error);
        res.status(500).send('Internal server error');
    }
});

router.post('/registerResponse', async (req, res) => {
    try {
        const { username, registerResponse } = req.body;
        const registerRequest = req.session.registerRequest;
        console.log('Register Request:', registerRequest);
        console.log('Register Response:', registerResponse);

        const registration = u2f.checkRegistration(registerRequest, registerResponse);
        console.log('Registration Result:', registration);

        if (registration.successful) {
            await User.findOneAndUpdate(
                { username },
                { $push: { devices: { keyHandle: registration.keyHandle, publicKey: registration.publicKey } } }
            );
            res.send('Device registered successfully');
        } else {
            res.status(400).send('Registration failed');
        }
    } catch (error) {
        console.error('Error in registerResponse:', error);
        res.status(500).send('Internal server error');
    }
});

router.post('/signRequest', async (req, res) => {
    try {
        const { username } = req.body;
        const user = await User.findOne({ username });

        if (user && user.devices.length > 0) {
            const signRequest = u2f.request('https://yubikeybe.onrender.com', user.devices.map(device => device.keyHandle));
            req.session.signRequest = signRequest;
            res.json(signRequest);
        } else {
            res.status(404).send('User or devices not found');
        }
    } catch (error) {
        console.error('Error in signRequest:', error);
        res.status(500).send('Internal server error');
    }
});

router.post('/signResponse', async (req, res) => {
    try {
        const { username, signResponse } = req.body;
        const signRequest = req.session.signRequest;
        const user = await User.findOne({ username });

        const device = user.devices.find(device => device.keyHandle === signResponse.keyHandle);
        const signCheck = u2f.checkSignature(signRequest, signResponse, device.publicKey);

        if (signCheck.successful) {
            res.send('Authentication successful');
        } else {
            res.status(400).send('Authentication failed');
        }
    } catch (error) {
        console.error('Error in signResponse:', error);
        res.status(500).send('Internal server error');
    }
});

module.exports = router;
