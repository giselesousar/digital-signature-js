const $ = require('jquery');
import { generateSelfSignCertificate, signFileWithPrivateKey, verifySignature } from './crypto'

const generatePrivateKeyAndCertificate = () => {
  openLoading();
  setTimeout(() => {
    const values = generateSelfSignCertificate('rsa', 'sha1');
    renderPrivateKeyandCertificate(values);
    closeLoading();
  }, 500);

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

const signFile = async () => {
  const fileToSign = readFile('#FileToSign');
  const privateKey = readFile('#PrivateKey');

  openLoading();
  try {
    const sigature = await signFileWithPrivateKey(fileToSign, privateKey, 'sha512');

    alert('The file has been successfully signed.');
    renderDownloadButton('#signFileButton', 'fileSigned.txt', sigature);
  } catch (err) {
    alert('An error has occurred. Please, try again!');
  }
  closeLoading();
}

const verify = async () => {
  const file = readFile('#fileInput');
  const sig = readFile('#signatureInput');
  const cert = readFile('#certificateInput');
  try {
    const result = await verifySignature(file, sig, cert, 'sha512');
    console.log(result);
  } catch (err) {
    alert('An error has occurred. Please, try again!');
  }
}

const readFile = (selector) => {
  return $(selector).prop('files')[0];
}

const openLoading = () => {
  $('#loadingModal').show();
}

const closeLoading = () => {
  $('#loadingModal').hide()
}

window.onload = () => {
  window.generatePrivateKeyAndCertificate = generatePrivateKeyAndCertificate;
  window.signFile = signFile;
  window.verify = verify;
}