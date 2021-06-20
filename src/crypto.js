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

    const certPem =  pki.certificateToPem(cert);
    const normal = pki.certificateFromPem(
        "-----BEGIN CERTIFICATE----- " +
"MIICvTCCAaWgAwIBAgIBATANBgkqhkiG9w0BAQUFADAiMQ8wDQYDVQQDEwZteS1h"+
"cHAxDzANBgNVBAoTBm15LWFwcDAeFw0yMTA2MjAwMzEyMDdaFw0yMTA2MjAwMzEy"+
"MDdaMCIxDzANBgNVBAMTBmRvbWFpbjEPMA0GA1UEChMGbXktYXBwMIIBIjANBgkq"+
"hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm8ET9EWz2l7tjRMBZ6TKJtqEW+aUMjbT"+
"0e15VLU32vjFPtWGzuwrmNOmDF0HG/ZwjcXS8WYsuCJpJftptIDfQZ2Cu3ZNtkEl"+
"ALLHMeZ4vcIJhqW63b6YAGiHe3hSxWTZ5yO9YOlSB6owPXMKV+Kl5RzYUhr27TO9"+
"K0AOXa3fuqepeAHXd9rHcMD+TLlP5zHeNlvxy919+WkjHCe5O0qQlEV6jxGcxguM"+
"MtA1VX49Rt8CCkvHOqZ6jdONrS5FRviZtCccEiTrUI4RdCO0Lt0XK/VGcfIiNPRw"+
"vW/WA4svgNRZDvgyYJlWbE7Uatx8aNNrnYhxcr70JK6cm/tforX4UwIDAQABMA0G"+
"CSqGSIb3DQEBBQUAA4IBAQA9w/PDlxcpdTxPkOUGWAD605OiRPjIqQfYgvn5I5pz"+
"gcMUIuNIxqMODOhsdModtvAbQlWBvhswhv1Y/U4g6R5XtJGX5gnM6MUc9hqM8bri"+
"JyqCA5Q1R2sHfDS354vXEEn6n1QztxJbVl96o7R83e851CCRc+HTgH4aLIkJSsao"+
"Z+15LNX+4SpBtbVyGSKajCyN8tXr5WT3MYLPpkwoOTUDalfdNBqwKhYG8iGwuMX0"+
"A9OnhdLUB5F4tW7v0j7QthTVONGMMeHOBmmAuGkm75xOYbDN+Sbd9sYBUS+y+pFL"+
"obuCKmj+5+EW+hPluCSWu78+SNubRDf7IkebrLrBy5qO"+
"-----END CERTIFICATE-----");
    console.log(normal);

    const verify = normal.publicKey.verify(normal.issuer.hash, `5n½ÂÓÙâêè#×Är#îèvøekYÜÝ"²RD]È4ÅH',VªÚøp{;¸G¡óÑuÞ5~°-oC6!ôÛ9,hÕZøÓæmé ³­´­"þL@f°ðÞ¸¹®9è¼©(ê:gO]Ôx3.mË0?où<pn8æ)ÛH¼]bG*TYÙF®¯'6êÒ7¯Ìf­N¼9;IA/ðF×	ì´ÞíV$b¯G*£umCxúÁtF¦ö	ÛÑîßeEéï$ßè#jJ#aè%6¼3ì¥x»"Ü`)

    console.log(verify)

    return {
        certificate: pki.certificateToPem(cert),
        privateKey: pki.privateKeyToPem(keys.privateKey)
    }
}

module.exports = {
    generateSelfSignCertificate
}