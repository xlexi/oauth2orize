function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

/**
 * Module dependencies.
 */
var utils = require('../utils'),
    TokenError = require('../errors/tokenerror');

/**
 * Refresh previously issued access tokens.
 *
 * This exchange middleware is used to by clients to refresh an access token by
 * using a refresh token issued by the server.
 *
 * Callbacks:
 *
 * This middleware requires an `issue` callback, for which the function
 * signature is as follows:
 *
 *     function(client, refreshToken, scope, done) { ... }
 *
 * `client` is the authenticated client instance attempting to obtain an access
 * token.  `refreshToken` is the refresh token issued by the server.  `scope` is
 * the scope of access requested by the client, which must not include any scope
 * not originally granted.  `done` is called to issue an access token:
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
 *     userProperty    property of `req` which contains the authenticated client (default: 'user')
 *     scopeSeparator  separator used to demarcate scope values (default: ' ')
 *
 * Examples:
 *
 *     server.exchange(oauth2orize.exchange.refreshToken(function(client, refreshToken, scope, done) {
 *       AccessToken.create(client, refreshToken, scope, function(err, accessToken) {
 *         if (err) { return done(err); }
 *         done(null, accessToken);
 *       });
 *     }));
 *
 * References:
 *  - [Refreshing an Access Token](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-6)
 *
 * @param {Object} options
 * @param {Function} issue
 * @api public
 */
module.exports = function (options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) {
    throw new TypeError('oauth2orize.refreshToken exchange requires an issue callback');
  }

  var userProperty = options.userProperty || 'user';

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [separators];
  }

  return function () {
    var ref = _asyncToGenerator(function* (ctx) {
      const req = ctx.request;
      if (!req.body) {
        throw new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?');
      }

      // The 'user' property of `req` holds the authenticated user.  In the case
      // of the token endpoint, the property will contain the OAuth 2.0 client.
      var client = ctx.state[userProperty],
          refreshToken = req.body.refresh_token,
          scope = req.body.scope;

      if (!refreshToken) {
        throw new TokenError('Missing required parameter: refresh_token', 'invalid_request');
      }

      if (scope) {
        for (var i = 0, len = separators.length; i < len; i++) {
          var separated = scope.split(separators[i]);
          // only separate on the first matching separator.  this allows for a sort
          // of separator "priority" (ie, favor spaces then fallback to commas)
          if (separated.length > 1) {
            scope = separated;
            break;
          }
        }
        if (!Array.isArray(scope)) {
          scope = [scope];
        }
      }

      var arity = issue.length;
      var result;
      if (arity == 3) {
        result = yield issue(client, refreshToken, scope);
      } else {
        // arity == 2
        result = yield issue(client, refreshToken);
      }

      var accessToken, params;
      if (Array.isArray(result)) {
        accessToken = result[0];
        refreshToken = result[1];
        params = result[2];
      } else {
        accessToken = result;
      }

      if (!accessToken) {
        throw new TokenError('Invalid refresh token', 'invalid_grant');
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

    return function refresh_token(_x) {
      return ref.apply(this, arguments);
    };
  }();
};