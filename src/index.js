const $ = require('jquery');
import { generateSelfSignCertificate } from './crypto'

const generatePrivateKeyAndCertificate = () => {
  openLoading();
  setTimeout(() => {
    const values = generateSelfSignCertificate('rsa', 'sha1');
    renderPrivateKeyandCertificate(values);
    closeLoading();
  }, 1000);

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

const openLoading = () => {
  $('#loadingModal').show();
}

const closeLoading = () => {
  $('#loadingModal').hide()
}

window.onload = () => {
  window.generatePrivateKeyAndCertificate = generatePrivateKeyAndCertificate;
}