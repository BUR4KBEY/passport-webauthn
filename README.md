# @burakbey/passport-fido2-webauthn

## ⭐ Main Reason for This Fork

In scenarios where frontend and backend applications are separated and run on different ports, the validator of this package will block requests due to differing origins, resulting in an `Origin mismatch` error. For example, if your backend's origin is `api.domain.tld` and your frontend's origin is `domain.tld`, the validator will reject the request because the origins do not match.

This fork introduces the environment variable `PASSPORT_FIDO2_WEBAUTHN_ALLOWED_ORIGINS`, allowing specification of acceptable origins. By default, the original behavior remains active. You can specify allowed origins by listing them with spaces as separators. For example, setting `PASSPORT_FIDO2_WEBAUTHN_ALLOWED_ORIGINS=https://domain.tld https://example.com` will permit both `https://domain.tld` and `https://example.com` to pass through the validator.

---

[Passport](https://www.passportjs.org/) strategy for authenticating
with [Web Authentication](https://www.w3.org/TR/webauthn-2/).

This module lets you authenticate using WebAuthn in your Node.js applications.
By plugging into Passport, WebAuthn-based sign in can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](https://github.com/senchalabs/connect#readme)-style middleware,
including [Express](https://expressjs.com/).

<div align="center">

:heart: [Sponsors](https://www.passportjs.org/sponsors/?utm_source=github&utm_medium=referral&utm_campaign=passport-fido2-webauthn&utm_content=nav-sponsors)

</div>

## Install

```sh
$ npm install @burakbey/passport-fido2-webauthn
```

## Usage

The WebAuthn authentication strategy authenticates users using a public
key-based credential. The authenticator which stores this credential is
typically the user's device or an external security key, either of which may be
unlocked using a PIN or biometric.

The strategy takes a `verify` function as an argument, which accepts `id` and
`userHandle` as arguments. `id` identifies a public key credential that has
been associated with a user's account. `userHandle` maps the credential to a
specific user account. When authenticating a user, this strategy obtains this
information from a WebAuthn assertion.

The `verify` function is responsible for determining the user to which the
account at the OP belongs. Once it has made a determination, it invokes `cb`
with the user record and a public key. The public key is used to
cryptographically verify the WebAuthn assertion, thus authenticating the user.

This strategy also takes a `register` function as an argument, which is called
when registering a new credential, and accepts `user`, `id` and `publicKey` as
arguments. `user` represents a specific user account with which to associate
the credential. `id` identifies the public key credential. `publicKey` is the
PEM-encoded public key.

The `register` function is responsible for associating the new credential with
the account. Once complete, it invokes `cb` with the user record.

Because the `verify` and `register` functions are supplied by the application,
the app is free to use any database of its choosing. The example below
illustrates usage of a SQL database.

```js
var WebAuthnStrategy = require('@burakbey/passport-fido2-webauthn');
var SessionChallengeStore =
  require('@burakbey/passport-fido2-webauthn').SessionChallengeStore;

var store = new SessionChallengeStore();

passport.use(
  new WebAuthnStrategy(
    { store: store },
    function verify(id, userHandle, cb) {
      db.get(
        'SELECT * FROM public_key_credentials WHERE external_id = ?',
        [id],
        function (err, row) {
          if (err) {
            return cb(err);
          }
          if (!row) {
            return cb(null, false, { message: 'Invalid key. ' });
          }
          var publicKey = row.public_key;
          db.get(
            'SELECT * FROM users WHERE rowid = ?',
            [row.user_id],
            function (err, row) {
              if (err) {
                return cb(err);
              }
              if (!row) {
                return cb(null, false, { message: 'Invalid key. ' });
              }
              if (Buffer.compare(row.handle, userHandle) != 0) {
                return cb(null, false, { message: 'Invalid key. ' });
              }
              return cb(null, row, publicKey);
            }
          );
        }
      );
    },
    function register(user, id, publicKey, cb) {
      db.run(
        'INSERT INTO users (username, name, handle) VALUES (?, ?, ?)',
        [user.name, user.displayName, user.id],
        function (err) {
          if (err) {
            return cb(err);
          }
          var newUser = {
            id: this.lastID,
            username: user.name,
            name: user.displayName
          };
          db.run(
            'INSERT INTO public_key_credentials (user_id, external_id, public_key) VALUES (?, ?, ?)',
            [newUser.id, id, publicKey],
            function (err) {
              if (err) {
                return cb(err);
              }
              return cb(null, newUser);
            }
          );
        }
      );
    }
  )
);
```

#### Define Routes

Two routes are needed in order to allow users to log in with their passkey or
security key.

The first route generates a randomized challenge, saves it in the
`ChallengeStore`, and sends it to the client-side JavaScript for it to be
included in the authenticator response. This is necessary in order to protect
against replay attacks.

```js
router.post('/login/public-key/challenge', function (req, res, next) {
  store.challenge(req, function (err, challenge) {
    if (err) {
      return next(err);
    }
    res.json({ challenge: base64url.encode(challenge) });
  });
});
```

The second route authenticates the authenticator assertion and logs the user in.

```js
router.post(
  '/login/public-key',
  passport.authenticate('webauthn', { failWithError: true }),
  function (req, res, next) {
    res.json({ ok: true });
  },
  function (err, req, res, next) {
    res.json({ ok: false });
  }
);
```

## Examples

- [todos-express-webauthn](https://github.com/passport/todos-express-webauthn)

  Illustrates how to use the WebAuthn strategy within an Express application.

## License

[The MIT License](https://opensource.org/licenses/MIT)

Copyright (c) 2019-2022 Jared Hanson <[https://www.jaredhanson.me/](https://www.jaredhanson.me/)>
