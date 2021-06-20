const $ = require('jquery');
import { generateSelfSignCertificate, signFileWithPrivateKey } from './crypto'

var fileToSign = null;
var privateKey = null;

const generatePrivateKeyAndCertificate = () => {
  const values = generateSelfSignCertificate('rsa', 'sha1');
  renderPrivateKeyandCertificate(values);
};

const renderPrivateKeyandCertificate = (values) => {
  $('#privateKeyTextarea').val(values.privateKey);
  $('#certificateTextarea').val(values.certificate);

  renderDownloadButton('#privateKeyButton', 'private_key.pem', values.privateKey);
  renderDownloadButton('#certificateButton', 'certificate.pem', values.certificate);
}

const renderDownloadButton = (selector, filename, content) => {
  $(selector).attr('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
  $(selector).attr('download', filename);
}

const receiveFileToSign = (evt) => {
  fileToSign = evt.files[0];
}

const receivePrivateKey = (evt) => {
  privateKey = evt.files[0];
}

const signFile = async () => {
  //talvez isso esteja errado, rever amanhã
  renderDownloadButton('#signFileButton', 'fileSigned.txt', await signFileWithPrivateKey(fileToSign, privateKey, 'sha1'));
}

window.onload = () => {
  window.generatePrivateKeyAndCertificate = generatePrivateKeyAndCertificate;
  window.receiveFileToSign = receiveFileToSign;
  window.receivePrivateKey = receivePrivateKey;
  window.signFile = signFile;

}