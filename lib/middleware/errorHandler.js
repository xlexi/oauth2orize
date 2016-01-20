function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

/**
 * Module dependencies.
 */
var UnorderedList = require('../unorderedlist');

/**
 * Handles errors encountered in OAuth 2.0 endpoints.
 *
 * This is error handling middleware intended for use in endpoints involved in
 * the OAuth 2.0 protocol.  If an error occurs while processing a request, this
 * middleware formats a response in accordance with the OAuth 2.0 specification.
 *
 * This middleware has two modes of operation: direct and indirect.  Direct mode
 * (the default) is intended to be used with the token endpoint, in which the
 * response can be sent directly to the client.  Indirect mode is intended to be
 * used with user authorization endpoints, in which the response must be issued
 * to the client indirectly via a redirect through the user's browser.
 *
 * Options:
 *   - `mode`   mode of operation, defaults to `direct`
 *
 * Examples:
 *
 *     app.post('/token',
 *       passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
 *       server.token(),
 *       server.errorHandler());
 *
 *    app.get('/dialog/authorize',
 *       login.ensureLoggedIn(),
 *       server.authorization( ... )
 *       server.errorHandler({ mode: 'indirect' }));
 *
 * References:
 *  - [Error Response](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.2)
 *  - [Authorization Response](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1.2)
 *  - [Authorization Response](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.2.2)
 *
 * @param {Object} options
 * @return {Function}
 * @api public
 */
module.exports = function (options) {
  options = options || {};

  var mode = options.mode || 'direct',
      fragment = options.fragment || ['token'],
      modes = options.modes || {};

  if (!modes.query) {
    modes.query = require('../response/query');
  }
  if (!modes.fragment) {
    modes.fragment = require('../response/fragment');
  }

  return function () {
    var ref = _asyncToGenerator(function* (ctx, next) {

      try {
        yield next();
      } catch (err) {
        if (mode == 'direct') {
          if (err.status) {
            ctx.status = err.status;
          }
          if (!ctx.status || ctx.status < 400) {
            ctx.status = 500;
          }

          if (ctx.status == 401) {
            // TODO: set WWW-Authenticate header
          }

          var e = {};
          e.error = err.code || 'server_error';
          if (err.message) {
            e.error_description = err.message;
          }
          if (err.uri) {
            e.error_uri = err.uri;
          }

          ctx.set('Content-Type', 'application/json');
          ctx.body = JSON.stringify(e);
          ctx.app.emit('error', err, ctx);
        } else if (mode == 'indirect') {
          // If the redirectURI for this OAuth 2.0 transaction is invalid, the user
          // agent will not be redirected and the client will not be informed.  `next`
          // immediately into the application's error handler, so a message can be
          // displayed to the user.
          if (!ctx.state.oauth2 || !ctx.state.oauth2.redirectURI) {
            throw err;
          }

          var enc = 'query';
          if (ctx.state.oauth2.req) {
            var type = new UnorderedList(ctx.state.oauth2.req.type);
            // In accordance with [OAuth 2.0 Multiple Response Type Encoding
            // Practices - draft 08](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html),
            // if the response type contains any value that requires fragment
            // encoding, the response will be fragment encoded.
            if (type.containsAny(fragment)) {
              enc = 'fragment';
            }
            if (ctx.state.oauth2.req.responseMode) {
              // Encode the response using the requested mode, if specified.
              enc = ctx.state.oauth2.req.responseMode;
            }
          }

          var respond = modes[enc],
              params = {};

          if (!respond) {
            throw err;
          }

          params.error = err.code || 'server_error';
          if (err.message) {
            params.error_description = err.message;
          }
          if (err.uri) {
            params.error_uri = err.uri;
          }
          if (ctx.state.oauth2.req && ctx.state.oauth2.req.state) {
            params.state = ctx.state.oauth2.req.state;
          }
          respond(ctx.state.oauth2, ctx.response, params);
        } else {
          throw err;
        }
      }
    });

    return function errorHandler(_x, _x2) {
      return ref.apply(this, arguments);
    };
  }();
};