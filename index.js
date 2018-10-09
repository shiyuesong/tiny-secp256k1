'use strict'

try {
  var binding = require('bindings')('secp256k1')
  delete binding.path

  // NaN drops function names, add them for is* (via toJSON)
  for (var key in binding) {
    if (key.indexOf('is') !== 0) continue

    binding[key].toJSON = function () { return key }
  }

  module.exports = binding
} catch (err) {
  module.exports = require('./ecurve')
}
