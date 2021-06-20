const forge = require('node-forge');

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
/**
 * certOptions = {
 *  hash,
 *  notBefore,
 *  notAfter
 * }
 */
function generateSelfSignCertificate(keySize, certOptions) {

    let pki = forge.pki;

    try {
        const keys = pki.rsa.generateKeyPair(Number(keySize));

        let cert = pki.createCertificate();

        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = certOptions?.notBefore ? new Date(certOptions.notBefore) : new Date();
        cert.validity.notAfter = certOptions?.notAfter ? new Date(certOptions.notAfter) : new Date();
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

        const md = createHash(certOptions.hash);
        
        cert.sign(keys.privateKey, md);

        return {
            certificate: pki.certificateToPem(cert),
            privateKey: pki.privateKeyToPem(keys.privateKey)
        }
    } catch (error) {
        throw error;
    }
}

async function signFileWithPrivateKey(file, privateKey, hashAlgorithm, padding, salt, encode) {

    file = await readFileAsync(file);

    try {
        let signature = null;

        filecontent = await readFileAsync(privateKey);
        const pk = forge.pki.privateKeyFromPem(filecontent);

        let md = createHash(hashAlgorithm);
        md.update(file, "utf8");

        if (padding == 'RSASSA-PSS') { //usa o padding RSASSA-PSS
            let pss = forge.pss.create({
                md: createHash(hashAlgorithm),
                mgf: forge.mgf.mgf1.create(createHash(hashAlgorithm)),
                saltLength: parseInt(salt || '20')
            });
            encode === "base64" ?
            signature = forge.util.encode64(pk.sign(md, pss))
            :
            signature = forge.util.encodeUtf8(pk.sign(md, pss))
        }
        else { //usa o padding RSASSA PKCS#1 v1.5
            encode === "base64" ?
            signature = forge.util.encode64(pk.sign(md))
            :
            signature = forge.util.encodeUtf8(pk.sign(md))
        }

        return signature;
    }
    catch (error) {
        alert('An error has occurred. Please, try again!');
    }
}

async function verifySignature(file, signature, certificate, hashAlgorithm, padding, salt, decode) {

    file = await readFileAsync(file);
    let verified = null;
    const sig = await readFileAsync(signature);
    const cert = await readFileAsync(certificate);

    const certFromPem = forge.pki.certificateFromPem(cert);

    md = createHash(hashAlgorithm);
    md.update(file, "utf8");

    if (padding == 'RSASSA-PSS') { //usa o padding RSASSA-PSS
        let pss = forge.pss.create({
            md: createHash(hashAlgorithm),
            mgf: forge.mgf.mgf1.create(createHash(hashAlgorithm)),
            saltLength: parseInt(salt || '20')
        });
        decode === "base64" ?
        verified = certFromPem.publicKey.verify(
            md.digest().getBytes(),
            forge.util.decode64(sig),
            pss
        )
        :
        verified = certFromPem.publicKey.verify(
            md.digest().getBytes(),
            forge.util.decodeUtf8(sig),
            pss
        )
    }
    else {
        decode === "base64" ?
        verified = certFromPem.publicKey.verify(
            md.digest().getBytes(),
            forge.util.decode64(sig)
        )
        :
        verified = certFromPem.publicKey.verify(
            md.digest().getBytes(),
            forge.util.decodeUtf8(sig)
        )
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