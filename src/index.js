/* eslint-disable no-console */
import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import forge from 'node-forge';
import unorm from 'unorm';
import hkdf from 'js-crypto-hkdf';
import trimLeft from 'trim-left';
import trimRight from 'trim-right';
import * as sha256 from 'fast-sha256';

const normaliseMasterPassword = password => {
    /* Trim white-spaces */
    const leftTrimmed = trimLeft(password);
    const rightTrimmed = trimRight(leftTrimmed);
    const combiningCharacters = /[\u0300-\u036F]/g;
    /* Normalisation */
    return unorm.nfkd(rightTrimmed).replace(combiningCharacters, '');
};

const generateSalt = () => {
    const salt = forge.random.getBytesSync(16);
    console.log('16 byte salt', salt);
    const email = 'ABC@gmail.com';
    const lowerCaseEmail = email.toLowerCase();
    console.log('lowercase email: ', lowerCaseEmail);
    // salt is salted with email
    return hkdf.compute(salt, 'SHA-256', 32, '', lowerCaseEmail).then(derived => {
        return derived.key;
    });
};

const generateDerivedKey = async () => {
    const normalisedMasterPassword = normaliseMasterPassword('masterPassword');
    console.log('normalised master password : ', normalisedMasterPassword);
    try {
        const salt = await generateSalt();
        console.log('32 byte salt : ', salt);
        return sha256.pbkdf2(normalisedMasterPassword, salt, 100000, 32);
    } catch (err) {
        console.log(err);
    }
};

// normalize master password first
// prepare 16 byte salt
// then to hash based key derivation function salted with lowercase version of email
// PBKDF2-HMAC-SHA256

class App extends Component {
    constructor(props) {
        super(props);
        this.state = { derivedKey: null };
    }

    async componentDidMount() {
        const key = await generateDerivedKey();
        this.setState({
            derivedKey: key,
        });
    }

    render() {
        return <div>32 Byte Derived Key : {this.state.derivedKey}</div>;
    }
}

ReactDOM.render(<App />, document.getElementById('root'));
