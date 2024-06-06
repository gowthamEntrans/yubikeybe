const express = require('express');
const { Fido2Lib } = require('fido2-lib');
const User = require('../models/User');
const router = express.Router();

const fido = new Fido2Lib({
    timeout: 60000,
    rpId: "yubikeybe.onrender.com",
    rpName: "Your App",
    challengeSize: 64,
    attestation: "direct",
    cryptoParams: [-7, -257],
    authenticatorAttachment: "cross-platform",
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "preferred"
});

router.post('/registerRequest', async (req, res) => {
    try {
        const { username } = req.body;
        let user = await User.findOne({ username });
        if (!user) {
            user = new User({ username, devices: [] });
            await user.save();
        }

        const registrationOptions = await fido.attestationOptions();
        req.session.challenge = registrationOptions.challenge;
        registrationOptions.user = {
            id: Buffer.from(username),
            name: username,
            displayName: username
        };
        res.json(registrationOptions);
    } catch (error) {
        console.error('Error in registerRequest:', error);
        res.status(500).send('Internal server error');
    }
});

router.post('/registerResponse', async (req, res) => {
    try {
        const { username, attestationResponse } = req.body;
        const challenge = req.session.challenge;
        const attestationExpectations = {
            challenge: challenge,
            origin: "https://yubikeybe.onrender.com",
            factor: "either"
        };

        const regResult = await fido.attestationResult(attestationResponse, attestationExpectations);

        await User.findOneAndUpdate(
            { username },
            { $push: { devices: regResult } }
        );
        res.send('Device registered successfully');
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
            const assertionOptions = await fido.assertionOptions();
            req.session.challenge = assertionOptions.challenge;
            assertionOptions.allowCredentials = user.devices.map(device => ({
                id: device.rawId,
                type: "public-key",
                transports: ["usb", "ble", "nfc"]
            }));
            res.json(assertionOptions);
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
        const { username, assertionResponse } = req.body;
        const challenge = req.session.challenge;
        const assertionExpectations = {
            challenge: challenge,
            origin: "https://yubikeybe.onrender.com",
            factor: "either",
            publicKey: user.devices[0].publicKey // Simplification, iterate through devices to find the matching one
        };

        const authnResult = await fido.assertionResult(assertionResponse, assertionExpectations);

        if (authnResult) {
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
