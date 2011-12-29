
var vows = require("vows"),
    assert = require("assert"),
    HKDF = require("../lib/hkdf");

var suite = vows.describe('all');

suite.addBatch({
  "an hkdf" : {
    topic: function() {
      var self = this;
      var hkdf = new HKDF('sha256', 'salt123', 'initialKeyingMaterial');
      hkdf.derive('info', 42, function(key) {
        // key is a Buffer, that can be serialized however one desires
        self.callback(null, key);
      });
    },
    "derives keys of the right length": function(err, key) {
      assert.equal(key.length, 42);
    }
  }
});

suite.addBatch({
  "test vector": {
    topic: function() {
      var self = this;
      
      var ikm = new Buffer("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 'hex');
      var salt = new Buffer("000102030405060708090a0b0c", 'hex');
      var info = new Buffer("f0f1f2f3f4f5f6f7f8f9", 'hex');

      var hkdf = new HKDF('sha256', salt, ikm);
      hkdf.derive(info, 42, function(key) {
        // key is a Buffer, that can be serialized however one desires
        self.callback(null, key);
      });
    },
    "works": function(err, output) {
      assert.equal(output.toString('hex'), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }
  }
})

suite.export(module);