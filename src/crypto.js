const forge = require('node-forge');

const generateKeyPair = (algorithm) => {
    switch (algorithm) {
        case 'rsa':
            return forge.pki.rsa.generateKeyPair();
        case 'ed25519':
            return forge.pki.ed25519.generateKeyPair();
        default:
            return forge.pki.rsa.generateKeyPair();
    }
    
}

const createHash = (hash) => {
    const md = forge.md;
    switch (hash) {
        case 'sha1':
            return md.sha1.create();
        case 'sha256':
            return md.sha256.create();
        case 'sha384':
            return md.sha384.create();
        case 'sha512':
            return md.sha512.create();
        case 'md5':
            return md.md5.create();
        default:
            return md.sha1.create();
    }
}

const generateSelfSignCertificate = (algorithm, hash) => {

    let pki = forge.pki;

    const keys = generateKeyPair(algorithm);

    let cert = pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    var attrsSubject = [{
        name: 'commonName',
        value: 'domain'
    }, {
        name: 'organizationName',
        value: 'my-app'
    }];
    var attrsIssuer = [{
        name: 'commonName',
        value: 'my-app'
    }, {
        name: 'organizationName',
        value: 'my-app'
    }];
    cert.setSubject(attrsSubject);
    cert.setIssuer(attrsIssuer);

    const md = createHash(hash);

    cert.sign(keys.privateKey, md);

    return {
        certificate: pki.certificateToPem(cert),
        privateKey: pki.privateKeyToPem(keys.privateKey)
    }
}

module.exports = {
    generateSelfSignCertificate
}