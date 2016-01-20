'use strict';
/**
 * Module dependencies.
 */
var AuthorizationError = require('../errors/authorizationerror');


/**
 * Handles requests to obtain a grant in the form of an authorization code.
 *
 * Callbacks:
 *
 * This middleware requires an `issue` callback, for which the function
 * signature is as follows:
 *
 *     function(client, redirectURI, user, ares, done) { ... }
 *
 * `client` is the client instance making the authorization request.
 * `redirectURI` is the redirect URI specified by the client, and used as a
 * verifier in the subsequent access token exchange.  `user` is the
 * authenticated user approving the request.  `ares` is any additional
 * parameters parsed from the user's decision, including scope, duration of
 * access, etc.  `done` is called to issue an authorization code:
 *
 *     done(err, code)
 *
 * `code` is the code that will be sent to the client.  If an error occurs,
 * `done` should be invoked with `err` set in idomatic Node.js fashion.
 *
 * The code issued in this step will be used by the client in exchange for an
 * access token.  This code is bound to the client identifier and redirection
 * URI, which is included in the token request for verification.  The code is a
 * single-use token, and should expire shortly after it is issued (the maximum
 * recommended lifetime is 10 minutes).
 *
 * Options:
 *
 *     scopeSeparator  separator used to demarcate scope values (default: ' ')
 *
 * Examples:
 *
 *     server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
 *       AuthorizationCode.create(client.id, redirectURI, user.id, ares.scope, function(err, code) {
 *         if (err) { return done(err); }
 *         done(null, code);
 *       });
 *     }));
 *
 * References:
 *  - [Authorization Code](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-1.3.1)
 *  - [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Object} module
 * @api public
 */
module.exports = function code(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.code grant requires an issue callback'); }

  var modes = options.modes || {};
  if (!modes.query) {
    modes.query = require('../response/query');
  }

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }


  /* Parse requests that request `code` as `response_type`.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
  function request(ctx) {

    var clientID = ctx.query.client_id
      , redirectURI = ctx.query.redirect_uri
      , scope = ctx.query.scope
      , state = ctx.query.state;

    if (!clientID) { throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request'); }

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

      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    };
  }

  /* Sends responses to transactions that request `code` as `response_type`.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */
  async function response(ctx) {
    const txn = ctx.state.oauth2;
    var mode = 'query'
      , respond;
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
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      return respond(txn, ctx.response, params);
    }

    // NOTE: The `redirect_uri`, if present in the client's authorization
    //       request, must also be present in the subsequent request to exchange
    //       the authorization code for an access token.  Acting as a verifier,
    //       the two values must be equal and serve to protect against certain
    //       types of attacks.  More information can be found here:
    //
    //       http://hueniverse.com/2011/06/oauth-2-0-redirection-uri-validation/

    var arity = issue.length;
    var code;
    if (arity == 5) {
      code = await issue(txn.client, txn.req.redirectURI, txn.user, txn.res, txn.req);
    } else if (arity == 4) {
      code = await issue(txn.client, txn.req.redirectURI, txn.user, txn.res);
    } else { // arity == 3
      code = await issue(txn.client, txn.req.redirectURI, txn.user);
    }

    if (!code) { throw new AuthorizationError('Request denied by authorization server', 'access_denied'); }

    params = { code: code };
    if (txn.req && txn.req.state) { params.state = txn.req.state; }

    respond(txn, ctx.response, params);
  }


  /**
   * Return `code` approval module.
   */
  var mod = {};
  mod.name = 'code';
  mod.request = request;
  mod.response = response;
  return mod;
};
