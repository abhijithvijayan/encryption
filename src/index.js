/* eslint-disable no-console */
import React, { Component } from 'react';
import ReactDOM from 'react-dom';

import unorm from 'unorm';
import bitwise from 'bitwise';
import forge from 'node-forge';
import trimLeft from 'trim-left';
import hkdf from 'js-crypto-hkdf';
import JSEncrypt from 'jsencrypt';
import trimRight from 'trim-right';
import jseu from 'js-encoding-utils';
import * as sha256 from 'fast-sha256';
import cryptoRandomString from 'crypto-random-string';

import jose from 'node-jose';

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

const deriveEncryptionKeySalt = () => {
    const uint8Salt = encodeEmail();
    const uint8MasterSecret = encodeSalt();
    return computeHKDF(uint8MasterSecret, uint8Salt);
};

const generateHashedKey = async () => {
    const normalisedMasterPassword = normMasterPassword('masterPassword');
    console.log('normalised master password : ', normalisedMasterPassword);
    const uint8MasterPassword = encodeMasterPassword(normalisedMasterPassword);
    try {
        const salt = await deriveEncryptionKeySalt(); // send to server
        console.log('32 byte salt : ', salt);
        // perform PBKDF2-HMAC-SHA256 hashing
        return sha256.pbkdf2(uint8MasterPassword, salt, 100000, 32);
    } catch (err) {
        console.log(err);
    }
};

const deriveIntermediateKey = (secretKey, accountId) => {
    const uint8Salt = stringToUint8Array(accountId);
    const uint8MasterSecret = stringToUint8Array(secretKey);
    return computeHKDF(uint8MasterSecret, uint8Salt);
};

const generateSecretKey = () => {
    const versionSetting = 'A1';
    const accountId = 'ABC123';
    const random26String = cryptoRandomString({ length: 26, characters: 'ABCDEFGHJKLMNPQRSTVWXYZ23456789' });
    const secretKey = versionSetting.concat(accountId, random26String);
    console.log('Secret Key : ', secretKey);
    return { accountId, secretKey };
};

function generateKeypair() {
    let crypt = null;
    let privateKey = null;
    crypt = new JSEncrypt({ default_key_size: 2056 });
    privateKey = crypt.getPrivateKey();
    // console.log(privateKey);
    // encrypt privatekey with MUK(Symmetric encryption is AES-256-GCM)
    // store to server

    // public key encryption is RSA-OAEP with 2048-bit moduli and a public exponent of 65537.
    return crypt.getPublicKey();
}

const keyToJWK = keyArray => {
    // Convert Typed Array, ArrayBuffer, or Array of Numbers to a Buffer
    const buffer = jose.util.asBuffer(keyArray);
    // convert from a Buffer to a base64uri-encoded String
    return jose.util.base64url.encode(buffer);
    // ToDo: Return as JWK object
};

class App extends Component {
    async componentDidMount() {
        /**
            Encryption Keys
        */
        const hashedKey = await generateHashedKey();
        console.log('hashed key: ', hashedKey);
        const { accountId, secretKey } = generateSecretKey();
        const intermediateKey = await deriveIntermediateKey(secretKey, accountId);
        console.log('Intermediate key : ', intermediateKey);
        // XOR Operation
        const XORedKey = bitwise.bits.xor(hashedKey, intermediateKey);
        // To Uint8Array
        const masterUnlockKey = new Uint8Array(XORedKey);
        console.log('master unlock key : ', masterUnlockKey);

        const base64uriString = keyToJWK(masterUnlockKey);
        console.log('base64url : ', base64uriString);

        // ToDo:
        // 1. Encrypt Private Key with MUK/KEK
        // 1. MUK to JWK (symmetric key : AES-256-GCM) (to store)
        // 3. Decrypting Vault Keys is done with Original Private Key
        // 4. Vault Keys are used to decrypt data

        /**
            Public-Private Keys
        */
        const publicKey = generateKeypair(); // send to server
        // console.log(publicKey);
    }

    render() {
        return <div>Look in the console!</div>;
    }
}

ReactDOM.render(<App />, document.getElementById('root'));
