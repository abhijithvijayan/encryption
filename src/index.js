/* eslint-disable no-unused-vars */
/* eslint-disable no-console */
import React, { Component } from 'react';
import ReactDOM from 'react-dom';

import unorm from 'unorm';
import jwt from 'jwt-simple';
import bitwise from 'bitwise';
import forge from 'node-forge';
import trimLeft from 'trim-left';
import hkdf from 'js-crypto-hkdf';
import JSEncrypt from 'jsencrypt';
import trimRight from 'trim-right';
import jseu from 'js-encoding-utils';
import JSONWebKey from 'json-web-key';
import * as sha256 from 'fast-sha256';
import cryptoRandomString from 'crypto-random-string';

import jose from 'node-jose';

import srpClient from 'secure-remote-password/client';

const { rsa } = forge.pki;

const performSRP = () => {
    const userId = 'user_123';
    const masterPassword = '$uper$ecure';

    const salt = srpClient.generateSalt();
    // compute x
    const privateKey = srpClient.derivePrivateKey(salt, userId, masterPassword);
    const verifier = srpClient.deriveVerifier(privateKey);

    console.log('salt', salt);
    //= > FB95867E...

    console.log('verifier', verifier);
};

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

// password key
const generateHashedKey = salt => {
    const normalisedMasterPassword = normMasterPassword('masterPassword');
    console.log('normalised master password : ', normalisedMasterPassword);
    const uint8MasterPassword = encodeMasterPassword(normalisedMasterPassword);
    console.log('32 byte salt : ', salt);
    // perform PBKDF2-HMAC-SHA256 hashing
    return sha256.pbkdf2(uint8MasterPassword, salt, 100000, 32);
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

const generateKeypair = async () => {
    const keypair = await rsa.generateKeyPair({ bits: 2048, workers: 2 });
    const { privateKey, publicKey } = keypair;
    // public key encryption is RSA-OAEP with 2048-bit moduli and a public exponent of 65537.
    return { privateKey, publicKey };
};

const keyTobase64uri = keyArray => {
    // convert from a Buffer to a base64uri-encoded String
    return jseu.encoder.encodeBase64Url(keyArray);
    // ToDo: use node-jose if JWK could be performed with it
    // return jose.util.base64url.encode(keyArray);
};

const encryptPrivateKeyWithSymmetricKey = (privateKey, symmetricKey) => {
    const { pki } = forge;
    // convert a Forge private key to an ASN.1 RSAPrivateKey
    const rsaPrivateKey = pki.privateKeyToAsn1(privateKey);
    // wrap an RSAPrivateKey ASN.1 object in a PKCS#8 ASN.1 PrivateKeyInfo
    const privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);
    // encrypts a PrivateKeyInfo and outputs an EncryptedPrivateKeyInfo
    return pki.encryptPrivateKeyInfo(privateKeyInfo, symmetricKey, {
        algorithm: 'aes256',
    });
};

const decryptPrivateKey = (encryptedPrivateKeyInfo, symmetricKey) => {
    const { pki } = forge;
    // decrypts an ASN.1 EncryptedPrivateKeyInfo that was encrypted with symmetric key
    const privateKeyInfo = pki.decryptPrivateKeyInfo(encryptedPrivateKeyInfo, symmetricKey);
    const privateKey = pki.privateKeyFromAsn1(privateKeyInfo);
    return privateKey;
};

const encryptVaultKeyWithPublicKey = (data, publicKey) => {
    // encrypt data with a public key using RSAES-OAEP/SHA-256
    return publicKey.encrypt(data, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
    });
};

const decryptVaultKeyWithPrivateKey = (encrypted, privateKey) => {
    // decrypt data with a private key using RSAES-OAEP/SHA-256
    return privateKey.decrypt(encrypted, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
    });
};

const generateSymmetricKey = () => {
    const key = forge.random.getBytesSync(32);
    const encodedSymmetricKey = stringToUint8Array(key);
    return keyTobase64uri(encodedSymmetricKey);
};

const encryptSymmetricKey = (symmetricKey, masterUnlockKey) => {
    const iv = forge.random.getBytesSync(12);
    // ToDo: FIX: use masterKey instead of random key
    const key = forge.random.getBytesSync(32);
    // encrypt some bytes using GCM mode
    const cipher = forge.cipher.createCipher('AES-GCM', key);
    cipher.start({
        iv, // should be a 12-byte binary-encoded string or byte buffer
        tagLength: 128, // optional, defaults to 128 bits
    });
    cipher.update(forge.util.createBuffer(symmetricKey));
    cipher.finish();
    const encryptedSymmetricKey = cipher.output;
    const { tag } = cipher.mode;
    return { encryptedSymmetricKey, tag };
};

class App extends Component {
    async componentDidMount() {
        /**
            Encryption Keys
        */
        const encryptionKeySalt = await deriveEncryptionKeySalt(); // send to server
        const hashedKey = await generateHashedKey(encryptionKeySalt);
        console.log('password key: ', hashedKey);

        const { accountId, secretKey } = generateSecretKey();
        const intermediateKey = await deriveIntermediateKey(secretKey, accountId);
        console.log('Intermediate key : ', intermediateKey);

        // XOR Operation
        const XORedKey = bitwise.bits.xor(hashedKey, intermediateKey);
        // To Uint8Array
        const masterUnlockKey = new Uint8Array(XORedKey);
        console.log('master unlock key : ', masterUnlockKey);

        // ToDo: Return as JWK object
        const base64uriMasterUnlockKey = keyTobase64uri(masterUnlockKey);
        console.log('base64uri-encoded MUK : ', base64uriMasterUnlockKey);

        // ToDo:
        // MUK to JWK (symmetric key : AES-256-GCM) (to store)

        /**
            Public-Private Keys
        */
        const { publicKey, privateKey } = await generateKeypair(); // send to server
        console.log('private/public keypair', publicKey, privateKey);

        const symmetricKey = generateSymmetricKey();
        console.log('base64uri symmetric key: ', symmetricKey);

        // Encrypt Private Key with Symmetric Key
        const encryptedPrivateKeyInfo = encryptPrivateKeyWithSymmetricKey(privateKey, symmetricKey);
        console.log('encryptedPrivateKeyInfo', encryptedPrivateKeyInfo);
        console.log('decryptedPrivateKey', decryptPrivateKey(encryptedPrivateKeyInfo, symmetricKey));

        // Encrypt Symmetric Key with MUK
        const { encryptedSymmetricKey, tag } = encryptSymmetricKey(symmetricKey, base64uriMasterUnlockKey);
        console.log('encryptSymmetricKey', encryptedSymmetricKey);

        // 32 bytes vault key
        const vaultKey = forge.random.getBytesSync(32);
        const encryptedVaultKey = encryptVaultKeyWithPublicKey(vaultKey, publicKey);
        console.log('Encrypted vault key: ', encryptedVaultKey);
        const decryptedVaultKey = decryptVaultKeyWithPrivateKey(encryptedVaultKey, privateKey);
        console.log('Decrypted vault key: ', decryptedVaultKey);
    }

    render() {
        return <div>Look at the console!</div>;
    }
}

ReactDOM.render(<App />, document.getElementById('root'));
