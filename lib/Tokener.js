// Class for generating and verifying tokens

const crypto = require('crypto')
const Moment = require('moment')
const DF = 'YYYYMMDD[T]HHmmss.SSS[Z]'

// Export only the class
class Tokener {
  // Store secret, set up options and private methods
  constructor (secret, opts) {
    if (typeof secret === 'string') {
      secret = Buffer.from(secret, 'ascii')
    }
    if (!Buffer.isBuffer(secret)) {
      throw new Error('Signing key must be string or Buffer')
    }
    // Set up raw signing method, getters
    const algo = (opts && opts.algorithm) || 'sha1'
    const sign = function (s) {
      const sig = crypto.createHmac(algo, secret).update(s).digest().toString('base64')
      return sig.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    }
    Object.defineProperty(this, 'sign', { get () { return sign } })
    Object.defineProperty(this, 'msValid', {
      get () {
        return (opts && opts.msValid) || 86400000
      }
    })
    // Create a sample to determine proper length, parse method
    const lenSig = this.sign('example').length
    const lenDate = Moment().format(DF).length
    const rxValid = new RegExp(`^(.*)\\.(.{${lenDate}})\\.(.{${lenSig}})$`)
    Object.defineProperty(this, 'tokenMatcher', { get () { return rxValid } })
    // throwOnError option rewrites verify() call
    if (opts && opts.throwOnError) {
      const normalVerify = this.verify
      this.verify = (token) => {
        let res = normalVerify.call(this, token)
        if (res instanceof Error) { throw res }
        return res
      }
    }
  }

  // Token generation
  create (toSign) {
    const expires = Moment.utc().add(this.msValid, 'ms').format(DF)
    const data = `${toSign}.${expires}`
    const sig = this.sign(data)
    return `${data}.${sig}`
  }

  // Token verification, returns original string, or Error
  verify (token) {
    if (typeof token !== 'string') { return new Error('No Token') }
    const parts = this.tokenMatcher.exec(token)
    if (!parts) { return new Error('Badly formatted Token') }
    const orig = parts[1]
    const expires = parts[2]
    const sig = parts[3]
    // First, check expiration
    const mm = Moment.utc(expires, DF, true)
    if (!mm.isValid()) { return new Error('Badly formatted Date') }
    if (!mm.isAfter(Moment())) { return new Error('Expired Token') }
    // Then, check signature
    const data = `${orig}.${expires}`
    const sigOK = this.sign(data)
    return sig === sigOK ? orig : new Error('Bad Token Signature')
  }
}

module.exports = Tokener
