###############################################################################
# Class for generating and verifying tokens
###############################################################################

crypto = require "crypto"
Moment = require("moment")
DF = "YYYYMMDD[T]HHmmss.SSS[Z]"

# Export only the class
module.exports = class Tokener
  # Store secret, set up options and private methods
  constructor: (secret, opts) ->
    if "string" is typeof secret
      secret = new Buffer(secret, "ascii")
    if not Buffer.isBuffer(secret)
      throw new Error("Signing key must be string or Buffer")
    # Set up raw signing method, getters
    algo = opts?.algorithm || "sha1"
    sign = (s) ->
      sig = crypto.createHmac(algo, secret).update(s).digest().toString('base64')
      sig.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    Object.defineProperty(@, "sign", {get: () -> sign})
    Object.defineProperty(@, "msValid", {get: () -> opts?.msValid || 86400000})
    # Create a sample to determine proper length, parse method
    lenSig = @sign("example").length
    lenDate = Moment().format(DF).length
    rxValid = new RegExp("^(.*)\.(.{#{lenDate}})\.(.{#{lenSig}})$")
    Object.defineProperty(@, "tokenMatcher", {get: () -> rxValid})
    # throwOnError option rewrites verify() call
    if opts?.throwOnError
      normalVerify = @verify
      @verify = (token) =>
        if (res = normalVerify.call(@, token)) instanceof Error
          throw res
        return res

  # Token generation
  create: (toSign) ->
    expires = Moment.utc().add(@msValid, "ms").format(DF)
    data = "#{toSign}.#{expires}"
    sig = @sign(data)
    return "#{data}.#{sig}"

  # Token verification, returns original string, or Error
  verify: (token) ->
    if "string" isnt typeof token
      return new Error("No Token")
    if not (parts = @tokenMatcher.exec(token))
      return new Error("Badly formatted Token")
    orig = parts[1]
    expires = parts[2]
    sig = parts[3]
    # First, check expiration
    if not (mm = Moment.utc(expires, DF, true)).isValid()
      return new Error("Badly formatted Date")
    if not mm.isAfter(Moment())
      return new Error("Expired Token")
    # Then, check signature
    data = "#{orig}.#{expires}"
    sigOK = @sign(data)
    if sig is sigOK then orig else new Error("Bad Token Signature")
