const forge = require('node-forge');

function generateKeyPair(algorithm) {
    try {
        switch (algorithm) {
            case 'rsa':
                return forge.pki.rsa.generateKeyPair();
            case 'ed25519':
                return forge.pki.ed25519.generateKeyPair();
            default:
                return forge.pki.rsa.generateKeyPair();
        }
    } catch (error) {
        throw error;
    }

}

function createHash(hash) {
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

function generateSelfSignCertificate(algorithm, hash) {

    let pki = forge.pki;

    try {
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
    } catch (error) {
        throw error;
    }
}

async function signFileWithPrivateKey(file, privateKey, hashAlgorithm, padding, saltLength, encodingScheme) {

    file = await readFileAsync(file);

    try {
        filecontent = await readFileAsync(privateKey);
        const pk = forge.pki.privateKeyFromPem(filecontent);
        let signature = null;
        let md = createHash(hashAlgorithm);
        md.update(file, "utf8");

        if (padding == 'RSASSA-PSS') { //usa o padding RSASSA-PSS
            let pss = forge.pss.create({
                md: createHash(hashAlgorithm),
                mgf: forge.mgf.mgf1.create(createHash(hashAlgorithm)),
                saltLength
            });

            if(encodingScheme === 'utf8'){
                signature = forge.util.encodeUtf8(pk.sign(md, pss));
            } else {
                signature = forge.util.encode64(pk.sign(md, pss));
            }

        }
        else { //usa o padding RSASSA PKCS#1 v1.5
            if(encodingScheme === 'utf8'){
                signature = forge.util.encodeUtf8(pk.sign(md));
            } else {
                signature = forge.util.encode64();
            }
        }

        return signature;
    }
    catch (error) {
        console.log(error);
    }
}

/**
 * 
 * @param {*} options object with file to verify, signature, certificate x.509,
 * hash algotithm used to sign, padding if rsa, salt lenght and encoding scheme
 * @returns 
 */

async function verifySignature(file, signature, certificate, hashAlgorithm, padding, saltLength, encodingScheme) {

    file = await readFileAsync(file);
    let verified = null;
    const sig = await readFileAsync(signature);
    const cert = await readFileAsync(certificate);

    const certFromPem = forge.pki.certificateFromPem(cert);

    md = createHash(hashAlgorithm);
    md.update(file, "utf8");

    let decoded = null;

        switch(encodingScheme) {
            case 'base64':
                decoded = forge.util.decode64(sig);
            case 'utf8':
                decoded = forge.util.decodeUtf8(sig);
        }


    if (padding == 'RSASSA-PSS') { //usa o padding RSASSA-PSS
        let pss = forge.pss.create({
            md: createHash(hashAlgorithm),
            mgf: forge.mgf.mgf1.create(createHash(hashAlgorithm)),
            saltLength
        });
        md = createHash(hashAlgorithm);
        md.update(file, "utf8");

        console.log(decoded);
        
        verified = certFromPem.publicKey.verify(
            md.digest().getBytes(),
            decoded,
            pss
        );
    }
    else { // padding RSASSA-PKCS1-V1_5
        verified = certFromPem.publicKey.verify(
            md.digest().getBytes(),
            decoded
        );
    }

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