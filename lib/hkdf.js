//
// a straightforward implementation of HKDF
//
// https://tools.ietf.org/html/rfc5869
//

var crypto = require("crypto");

function zeros(length) {
  var buf = new Buffer(length);

  // XXX is this the character zero, or the byte 0.
  buf.fill("0");

  return buf.toString();
}
// imk is initial keying material
function HKDF(hashAlg, salt, ikm) {
  this.hashAlg = hashAlg;

  // create the hash alg to see if it exists and get its length
  var hash = crypto.createHash(this.hashAlg);
  this.hashLength = hash.digest().length;

  this.salt = salt || zeros(this.hashLength);
  this.ikm = ikm;

  // now we compute the PRK
  var hmac = crypto.createHmac(this.hashAlg, this.salt);
  hmac.update(this.ikm);
  this.prk = hmac.digest();
}

HKDF.prototype = {
  derive: function(info, size, cb) {
    var prev = "";
    var output = new Buffer(size);
    var num_blocks = Math.ceil(size / this.hashLength);

    for (var i=0; i<num_blocks; i++) {
      var hmac = crypto.createHmac(this.hashAlg, this.prk);
      var input = prev + info + (0x01 * (i+1));
      hmac.update(input);
      prev = hmac.digest();
      output.write(prev, this.hashLength * i, this.hashLength, 'binary');
    }

    process.nextTick(function() {cb(output);});
  }
};

module.exports = HKDF;