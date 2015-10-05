/**
 * just exports the tokener instantiation
 */
var Tokener = require("./lib/Tokener");

module.exports = function(secret, opts) {
    return new Tokener(secret, opts);
};
