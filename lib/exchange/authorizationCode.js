function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

/**
 * Module dependencies.
 */
var utils = require('../utils'),
    TokenError = require('../errors/tokenerror');

/**
 * Exchanges authorization codes for access tokens.
 *
 * This exchange middleware is used to by clients to obtain an access token by
 * presenting an authorization code.  An authorization code must have previously
 * been issued, as handled by `code` grant middleware.
 *
 * Callbacks:
 *
 * This middleware requires an `issue` callback, for which the function
 * signature is as follows:
 *
 *     function(client, code, redirectURI, done) { ... }
 *
 * `client` is the authenticated client instance attempting to obtain an access
 * token.  `code` is the authorization code the client is in possession of.
 * `redirectURI` is the redirect URI specified by the client, being used as a
 * verifier which must match the value in the initial authorization request.
 * `done` is called to issue an access token:
 *
 *     done(err, accessToken, refreshToken, params)
 *
 * `accessToken` is the access token that will be sent to the client.  An
 * optional `refreshToken` will be sent to the client, if the server chooses to
 * implement support for this functionality.  Any additional `params` will be
 * included in the response.  If an error occurs, `done` should be invoked with
 * `err` set in idomatic Node.js fashion.
 *
 * Options:
 *
 *     userProperty   property of `req` which contains the authenticated client (default: 'user')
 *
 * Examples:
 *
 *     server.exchange(oauth2orize.exchange.authorizationCode(function(client, code, redirectURI, done) {
 *       AccessToken.create(client, code, redirectURI, function(err, accessToken) {
 *         if (err) { return done(err); }
 *         done(null, accessToken);
 *       });
 *     }));
 *
 * References:
 *  - [Authorization Code](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-1.3.1)
 *  - [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Function}
 * @api public
 */
module.exports = function (options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) {
    throw new TypeError('oauth2orize.authorizationCode exchange requires an issue callback');
  }

  var userProperty = options.userProperty || 'user';

  return function () {
    var ref = _asyncToGenerator(function* (ctx) {
      const req = ctx.request;
      if (!req.body) {
        throw new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?');
      }

      // The 'user' property of `req` holds the authenticated user.  In the case
      // of the token endpoint, the property will contain the OAuth 2.0 client.
      var client = ctx.state[userProperty],
          code = req.body.code,
          redirectURI = req.body.redirect_uri;

      if (!code) {
        throw new TokenError('Missing required parameter: code', 'invalid_request');
      }

      var arity = issue.length;
      var result;
      if (arity == 4) {
        result = yield issue(client, code, redirectURI, req.body);
      } else {
        // arity == 3
        result = yield issue(client, code, redirectURI);
      }

      var accessToken, refreshToken, params;
      if (Array.isArray(result)) {
        accessToken = result[0];
        refreshToken = result[1];
        params = result[2];
      } else {
        accessToken = result;
      }

      if (!accessToken) {
        throw new TokenError('Invalid authorization code', 'invalid_grant');
      }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }

      var tok = {};
      tok.access_token = accessToken;
      if (refreshToken) {
        tok.refresh_token = refreshToken;
      }
      if (params) {
        utils.merge(tok, params);
      }
      tok.token_type = tok.token_type || 'Bearer';

      var json = JSON.stringify(tok);
      ctx.set('Content-Type', 'application/json');
      ctx.set('Cache-Control', 'no-store');
      ctx.set('Pragma', 'no-cache');
      ctx.body = json;
    });

    return function authorization_code(_x) {
      return ref.apply(this, arguments);
    };
  }();
};