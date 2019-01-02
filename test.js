require('should')
var tokener = require('./')

describe('Tokener', function () {
  it('should create valid tokens', function () {
    var signer = tokener('foobar')
    var orig = 'a:b:c'
    var signed = signer.create(orig)
    signer.verify(signed).should.equal(orig)
  })

  it('should allow another algorithm', function () {
    var signer = tokener('foobar')
    var signer2 = tokener('foobar', { algorithm: 'sha256' })
    var orig = 'a:b:c'
    var signed = signer.create(orig)
    var signed2 = signer2.create(orig)
    // they should not equal each other, but both be correct
    signed.should.not.equal(signed2)
    signer.verify(signed).should.equal(orig)
    signer2.verify(signed2).should.equal(orig)
  })

  it('should allow Error-throwing mode', function () {
    var signer = tokener('foobar', { throwOnError: true })
    var orig = 'foo:bar:baz'
    signer.verify(signer.create(orig)).should.equal(orig);
    (function throwOnBadToken () {
      signer.verify('bad, bad token')
    }).should.throw()
  })

  it('should reject expired tokens', function (done) {
    var signer = tokener('foobar', { msValid: 10 })
    var orig = '99 bottles on the wall'
    var signed = signer.create(orig)
    signer.verify(signed).should.equal(orig)
    setTimeout(function () {
      var e = signer.verify(signed);
      (e instanceof Error).should.be.true()
      done()
    }, 20)
  })

  it('should reject mangled tokens', function () {
    var signer = tokener('foobar')
    var orig = 'abc'
    var signed = signer.create(orig)
    signed = signed.replace(/^abc/, 'def')
    var e = signer.verify(signed);
    (e instanceof Error).should.be.true()
    e.message.should.equal('Bad Token Signature')
  })

  it('should reject non-tokens', function () {
    var signer = tokener('foobar')
    var e = signer.verify('the evil user changed me');
    (e instanceof Error).should.be.true()
    e.message.should.equal('Badly formatted Token')
  })

  it('should reject badly formatted dates', function () {
    var signer = tokener('foobar')
    var fakeSig = '012345678901234567890123456'
    var e = signer.verify('a:b:c.this is a bad date k.' + fakeSig);
    (e instanceof Error).should.be.true()
    e.message.should.equal('Badly formatted Date')
  })

  it('should not instantiate with bad args', function () {
    (function () {
      var signer = tokener('asdf')
    }).should.not.throw();
    (function () {
      var signer = tokener(Buffer.from([1, 2, 3]))
    }).should.not.throw();
    (function () {
      var signer = tokener()
    }).should.throw();
    (function () {
      var signer = tokener('asdf', { algorithm: 'foobar' })
    }).should.throw()
  })
})
