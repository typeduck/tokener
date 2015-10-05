# Tokener

Generate and verify ephemeral tokens.

The inspiration behind this API comes from
[here](https://pdos.csail.mit.edu/papers/webauth:sec10.pdf).

## Instantiation

```javascript
var tokener = require("tokener");

// Signing key is required, everything else is optional
var signer = tokener("SIGNING KEY HERE", {
  algorithm: "sha1",   // from crypto module
  msValid: 86400000,   // 1 day is default (milliseconds!)
  throwOnError: false  // can change verify method to throw
});
```

## Signing

```javascript
var token = signer.create("some data to sign");
```

## Verification

```javascript
var data = signer.verify(token); // this will throw when throwOnError is true
if ( data instanceof Error ) {
  // uh-oh, token could NOT be verified, or was expired
}
else {
  // we're good!
}
```
