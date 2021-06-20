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
    cert.validity.notBefore = new Date('06-19-2021');
    cert.validity.notAfter = new Date('06-21-2021');
    var attrsSubject = [{
        name: 'commonName',
        value: 'Client'
    }, {
        name: 'organizationName',
        value: 'Client'
    }];
    var attrsIssuer = [{
        name: 'commonName',
        value: 'Self sign certificate'
    }, {
        name: 'organizationName',
        value: 'Self sign certificate'
    }];
    cert.setSubject(attrsSubject);
    cert.setIssuer(attrsIssuer);

    const md = createHash(hash);

    cert.md = md;

    cert.sign(keys.privateKey, md);

    return {
        certificate: pki.certificateToPem(cert),
        privateKey: pki.privateKeyToPem(keys.privateKey)
    }
}

async function signFileWithPrivateKey(file, privateKey, hashAlgorithm) {

    file = await readFileAsync(file);

    try {
        filecontent = await readFileAsync(privateKey);
        const pk = forge.pki.privateKeyFromPem(filecontent);

        let pss = forge.pss.create({
            md: createHash(hashAlgorithm),
            mgf: forge.mgf.mgf1.create(createHash(hashAlgorithm)),
            saltLength: 20
        });
        let md = createHash(hashAlgorithm);
        md.update(file, "utf8");

        let signature = forge.util.encode64(pk.sign(md, pss));

        return signature;
    }
    catch (error) {
        console.log(error);
    }
}

async function verifySignature(file, signature, certificate, hashAlgorithm) {

    file = await readFileAsync(file);

    const sig = await readFileAsync(signature);
    const cert = await readFileAsync(certificate);

    const certFromPem = forge.pki.certificateFromPem(cert);

    let pss = forge.pss.create({
        md: createHash(hashAlgorithm),
        mgf: forge.mgf.mgf1.create(createHash(hashAlgorithm)),
        saltLength: 20
    });
    md = createHash(hashAlgorithm);
    md.update(file, "utf8");
    
    let verified = certFromPem.publicKey.verify(
        md.digest().getBytes(),
        forge.util.decode64(sig),
        pss
    );

    return verified;
}

function readFileAsync(file) {
    return new Promise((resolve, reject) => {
        let reader = new FileReader();

        reader.onload = function (evt) {
            if (evt.target.readyState != 2) return;
            if (evt.target.error) {
                return;
            }
            resolve(evt.target.result);
        };

        reader.onerror = reject;
        reader.readAsText(file);
    })
}

module.exports = {
    generateSelfSignCertificate,
    signFileWithPrivateKey,
    verifySignature
}