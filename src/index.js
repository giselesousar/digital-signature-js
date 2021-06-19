const $ = require('jquery');
import { generateSelfSignCertificate } from './crypto'

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

window.onload = () => {
  window.generatePrivateKeyAndCertificate = generatePrivateKeyAndCertificate;
}