function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

/**
 * Module dependencies.
 */
var AuthorizationError = require('../errors/authorizationerror'),
    BadRequestError = require('../errors/badrequesterror'),
    ForbiddenError = require('../errors/forbiddenerror');

/**
 * Loads an OAuth 2.0 authorization transaction from the session.
 *
 * This middleware is used to load a pending OAuth 2.0 transaction that is
 * serialized into the session.  In most circumstances, this is transparently
 * done prior to processing a user's decision with `decision` middleware, and an
 * implementation shouldn't need to mount this middleware explicitly.
 *
 * Options:
 *
 *     transactionField  name of field that contains the transaction ID (default: 'transaction_id')
 *     sessionKey        key under which transactions are stored in the session (default: 'authorize')
 *
 * @param {Server} server
 * @param {Object} options
 * @return {Function}
 * @api protected
 */
module.exports = function (server, options) {
  options = options || {};

  if (!server) {
    throw new TypeError('oauth2orize.transactionLoader middleware requires a server argument');
  }

  var field = options.transactionField || 'transaction_id',
      key = options.sessionKey || 'authorize';

  return function () {
    var ref = _asyncToGenerator(function* (ctx, next) {
      if (!ctx.session) {
        throw new Error('OAuth2orize requires session support. Did you forget app.use(express.session(...))?');
      }
      if (!ctx.session[key]) {
        throw new ForbiddenError('Unable to load OAuth 2.0 transactions from session');
      }

      var query = ctx.query || {},
          body = ctx.request.body || {},
          tid = query[field] || body[field];

      if (!tid) {
        throw new BadRequestError('Missing required parameter: ' + field);
      }
      var txn = ctx.session[key][tid];
      if (!txn) {
        throw new ForbiddenError('Unable to load OAuth 2.0 transaction: ' + tid);
      }

      const client = yield server.deserializeClient(txn.client);
      if (!client) {
        // At the time the request was initiated, the client was validated.
        // Since then, however, it has been invalidated.  The transaction will
        // be invalidated and no response will be sent to the client.
        delete ctx.session[key][tid];
        throw new AuthorizationError('Unauthorized client', 'unauthorized_client');
      }

      ctx.state.oauth2 = {};
      ctx.state.oauth2.transactionID = tid;
      ctx.state.oauth2.client = client;
      ctx.state.oauth2.redirectURI = txn.redirectURI;
      ctx.state.oauth2.req = txn.req;
      ctx.state.oauth2.info = txn.info;

      yield next();
    });

    return function transactionLoader(_x, _x2) {
      return ref.apply(this, arguments);
    };
  }();
};