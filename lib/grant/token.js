'use strict';
/**
 * Module dependencies.
 */

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

var utils = require('../utils'),
    AuthorizationError = require('../errors/authorizationerror');

/**
 * Handles requests to obtain an implicit grant.
 *
 * Callbacks:
 *
 * This middleware requires an `issue` callback, for which the function
 * signature is as follows:
 *
 *     function(client, user, ares, done) { ... }
 *
 * `client` is the client instance making the authorization request.  `user` is
 * the authenticated user approving the request.  `ares` is any additional
 * parameters parsed from the user's decision, including scope, duration of
 * access, etc.  `done` is called to issue an access token:
 *
 *     done(err, accessToken, params)
 *
 * `accessToken` is the access token that will be sent to the client.
 * Optionally, any additional `params` will be included in the response.  If an
 * error occurs, `done` should be invoked with `err` set in idomatic Node.js
 * fashion.
 *
 * Implicit grants do not include client authentication, and rely on the
 * registration of the redirect URI.  Applications can enforce this constraint
 * in the `validate` callback of `authorization` middleware.
 *
 * Options:
 *
 *     scopeSeparator  separator used to demarcate scope values (default: ' ')
 *
 * Examples:
 *
 *     server.grant(oauth2orize.grant.token(function(client, user, ares, done) {}
 *       AccessToken.create(client, user, ares.scope, function(err, accessToken) {
 *         if (err) { return done(err); }
 *         done(null, accessToken);
 *       });
 *     }));
 *
 * References:
 *  - [Implicit](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-1.3.2)
 *  - [Implicit Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.2)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Object} module
 * @api public
 */
module.exports = function token(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) {
    throw new TypeError('oauth2orize.token grant requires an issue callback');
  }

  var modes = options.modes || {};
  if (!modes.fragment) {
    modes.fragment = require('../response/fragment');
  }

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [separators];
  }

  /* Parse requests that request `token` as `response_type`.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
  function request(ctx) {
    var clientID = ctx.query.client_id,
        redirectURI = ctx.query.redirect_uri,
        scope = ctx.query.scope,
        state = ctx.query.state;

    if (!clientID) {
      throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request');
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

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    };
  }

  /* Sends responses to transactions that request `token` as `response_type`.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */

  let response = function () {
    var ref = _asyncToGenerator(function* (ctx) {
      const txn = ctx.state.oauth2;
      var mode = 'fragment',
          respond;
      if (txn.req && txn.req.responseMode) {
        mode = txn.req.responseMode;
      }
      respond = modes[mode];

      if (!respond) {
        // http://lists.openid.net/pipermail/openid-specs-ab/Week-of-Mon-20140317/004680.html
        throw new AuthorizationError('Unsupported response mode: ' + mode, 'unsupported_response_mode', null, 501);
      }
      if (respond && respond.validate) {
        respond.validate(txn);
      }

      if (!txn.res.allow) {
        var params = { error: 'access_denied' };
        if (txn.req && txn.req.state) {
          params.state = txn.req.state;
        }
        return respond(txn, ctx.response, params);
      }

      // NOTE: In contrast to an authorization code grant, redirectURI is not
      //       passed as an argument to the issue callback because it is not used
      //       as a verifier in a subsequent token exchange.  However, when
      //       issuing an implicit access tokens, an application must ensure that
      //       the redirection URI is registered, which can be done in the
      //       `validate` callback of `authorization` middleware.

      var arity = issue.length;
      var result;
      if (arity == 3) {
        result = yield issue(txn.client, txn.user, txn.res);
      } else {
        // arity == 2
        result = yield issue(txn.client, txn.user);
      }

      var accessToken;
      if (Array.isArray(result)) {
        accessToken = result[0];
        params = result[1];
      } else {
        accessToken = result;
        params = undefined;
      }

      if (!accessToken) {
        throw new AuthorizationError('Request denied by authorization server', 'access_denied');
      }

      var tok = {};
      tok.access_token = accessToken;
      if (params) {
        utils.merge(tok, params);
      }
      tok.token_type = tok.token_type || 'Bearer';
      if (txn.req && txn.req.state) {
        tok.state = txn.req.state;
      }
      return respond(txn, ctx.response, tok);
    });

    return function response(_x) {
      return ref.apply(this, arguments);
    };
  }();

  /**
   * Return `token` approval module.
   */

  var mod = {};
  mod.name = 'token';
  mod.request = request;
  mod.response = response;
  return mod;
};