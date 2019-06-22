/* eslint-disable no-console */
import React, { Component } from 'react';
import ReactDOM from 'react-dom';

import unorm from 'unorm';
import forge from 'node-forge';
import trimLeft from 'trim-left';
import hkdf from 'js-crypto-hkdf';
import trimRight from 'trim-right';
import jseu from 'js-encoding-utils';
import * as sha256 from 'fast-sha256';
import secureRandom from 'secure-random';
import cryptoRandomString from 'crypto-random-string';

const normMasterPassword = password => {
    /* Trim white-spaces from master password */
    const leftTrimmed = trimLeft(password);
    const rightTrimmed = trimRight(leftTrimmed);
    const combiningCharacters = /[\u0300-\u036F]/g;
    /* nfkd Normalisation */
    return unorm.nfkd(rightTrimmed).replace(combiningCharacters, '');
};

const stringToUint8Array = string => {
    return jseu.encoder.stringToArrayBuffer(string);
};

const encodeMasterPassword = password => {
    /* encode the password to Uint8Array */
    return stringToUint8Array(password);
};

const encodeEmail = () => {
    const email = 'ABC@example.com';
    const lowerCaseEmail = email.toLowerCase();
    console.log('lowercase email: ', lowerCaseEmail);
    /* encode the email to Uint8Array */
    return stringToUint8Array(lowerCaseEmail);
};

const encodeSalt = () => {
    /* 16 bytes random salt */
    const salt = forge.random.getBytesSync(16);
    console.log('16 byte salt', salt);
    /* encode the salt to Uint8Array */
    return stringToUint8Array(salt);
};

const computeHKDF = (uint8MasterSecret, uint8Salt) => {
    /* Hash-based Key Derivation Function */
    return hkdf.compute(uint8MasterSecret, 'SHA-256', 32, '', uint8Salt).then(derived => {
        return derived.key;
    });
};

const deriveKey = () => {
    const uint8Salt = encodeEmail();
    const uint8MasterSecret = encodeSalt();
    return computeHKDF(uint8MasterSecret, uint8Salt);
};

const generateSecretKey = () => {
    const versionSetting = 'A1';
    const accountId = 'ABC123';
    const random26String = cryptoRandomString({ length: 26, characters: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890' });
    const secretKey = versionSetting.concat(accountId, random26String);
    console.log('Secret Key : ', secretKey);
    return secretKey;
};

const generateHashedKey = async () => {
    const normalisedMasterPassword = normMasterPassword('masterPassword');
    console.log('normalised master password : ', normalisedMasterPassword);
    const uint8MasterPassword = encodeMasterPassword(normalisedMasterPassword);
    try {
        const salt = await deriveKey();
        console.log('32 byte salt : ', salt);
        const hashedKey = sha256.pbkdf2(uint8MasterPassword, salt, 100000, 32);
        console.log('hashed key: ', hashedKey);
        return hashedKey;
    } catch (err) {
        console.log(err);
    }
};

// normalize master password first
// prepare 16 byte salt
// then to hash based key derivation function salted with lowercase version of email
// PBKDF2-HMAC-SHA256

class App extends Component {
    async componentDidMount() {
        await generateHashedKey();
        generateSecretKey();
    }

    render() {
        return <div>Look in the console!</div>;
    }
}

ReactDOM.render(<App />, document.getElementById('root'));
