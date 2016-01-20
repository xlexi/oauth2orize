'use strict';
/**
 * Module dependencies.
 */

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

var compose = require('koa-compose');
var UnorderedList = require('./unorderedlist'),
    authorization = require('./middleware/authorization'),
    decision = require('./middleware/decision'),
    transactionLoader = require('./middleware/transactionLoader'),
    token = require('./middleware/token'),
    errorHandler = require('./middleware/errorHandler'),
    utils = require('./utils'),
    debug = require('debug')('oauth2orize');

/**
 * `Server` constructor.
 *
 * @api public
 */
function Server() {
  this._reqParsers = [];
  this._resHandlers = [];
  this._exchanges = [];

  this._serializers = [];
  this._deserializers = [];
}

/**
 * Register authorization grant middleware.
 *
 * OAuth 2.0 defines an authorization framework, in which authorization grants
 * can be of a variety of types.  Initiating and responding to an OAuth 2.0
 * authorization transaction is implemented by grant middleware, and the server
 * registers the middleware it wishes to support.
 *
 * Examples:
 *
 *     server.grant(oauth2orize.grant.code());
 *
 *     server.grant('*', function(req) {
 *       return { host: req.headers['host'] }
 *     });
 *
 *     server.grant('foo', function(req) {
 *       return { foo: req.query['foo'] }
 *     });
 *
 * @param {String|Object} type
 * @param {String} phase
 * @param {Function} fn
 * @return {Server} for chaining
 * @api public
 */
Server.prototype.grant = function (type, phase, fn) {
  if (typeof type == 'object') {
    // sig: grant(mod)
    var mod = type;
    if (mod.request) {
      this.grant(mod.name, 'request', mod.request);
    }
    if (mod.response) {
      this.grant(mod.name, 'response', mod.response);
    }
    return this;
  }
  if (typeof phase == 'object') {
    // sig: grant(type, mod)
    var mod = phase;
    if (mod.request) {
      this.grant(type, 'request', mod.request);
    }
    if (mod.response) {
      this.grant(type, 'response', mod.response);
    }
    return this;
  }

  if (typeof phase == 'function') {
    // sig: grant(type, fn)
    fn = phase;
    phase = 'request';
  }
  if (type === '*') {
    type = null;
  }
  if (type) {
    type = new UnorderedList(type);
  }

  if (phase == 'request') {
    debug('register request parser %s %s', type || '*', fn.name || 'anonymous');
    this._reqParsers.push({ type: type, handle: fn });
  } else if (phase == 'response') {
    debug('register response handler %s %s', type || '*', fn.name || 'anonymous');
    this._resHandlers.push({ type: type, handle: fn });
  }
  return this;
};

/**
 * Register token exchange middleware.
 *
 * OAuth 2.0 defines an authorization framework, in which authorization grants
 * can be of a variety of types.  Exchanging of these types for access tokens is
 * implemented by exchange middleware, and the server registers the middleware
 * it wishes to support.
 *
 * Examples:
 *
 *     server.exchange(oauth2orize.exchange.authorizationCode(function() {
 *       ...
 *     }));
 *
 * @param {String|Function} type
 * @param {Function} fn
 * @return {Server} for chaining
 * @api public
 */
Server.prototype.exchange = function (type, fn) {
  if (typeof type == 'function') {
    fn = type;
    type = fn.name;
  }
  if (type === '*') {
    type = null;
  }

  debug('register exchanger %s %s', type || '*', fn.name || 'anonymous');
  this._exchanges.push({ type: type, handle: fn });
  return this;
};

/**
 * Parses requests to obtain authorization.
 *
 * @api public
 */
Server.prototype.authorize = Server.prototype.authorization = function (options, validate, immediate) {
  return authorization(this, options, validate, immediate);
};

/**
 * Handle a user's response to an authorization dialog.
 *
 * @api public
 */
Server.prototype.decision = function (options, parse) {
  if (options && options.loadTransaction === false) {
    return decision(this, options, parse);
  }
  return [transactionLoader(this, options), decision(this, options, parse)];
};

/**
 * Handle requests to exchange an authorization grant for an access token.
 *
 * @api public
 */
Server.prototype.token = function (options) {
  return token(this, options);
};

/**
 * Respond to errors encountered in OAuth 2.0 endpoints.
 *
 * @api public
 */
Server.prototype.errorHandler = function (options) {
  return errorHandler(options);
};

/**
 * Registers a function used to serialize client objects into the session.
 *
 * Examples:
 *
 *     server.serializeClient(function(client, done) {
 *       done(null, client.id);
 *     });
 *
 * @api public
 */
Server.prototype.serializeClient = function () {
  var ref = _asyncToGenerator(function* (fn) {
    if (typeof fn === 'function') {
      return this._serializers.push(fn);
    }

    // private implementation that traverses the chain of serializers, attempting
    // to serialize a client
    var client = fn;

    var stack = this._serializers;

    for (var i = 0;; i++) {
      let layer = stack[i];

      if (!layer) {
        throw new Error('Failed to serialize client. Register serialization function using serializeClient().');
      }

      let obj = yield layer(client);
      if (obj) {
        return obj;
      }
    }
  });

  return function (_x) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Registers a function used to deserialize client objects out of the session.
 *
 * Examples:
 *
 *     server.deserializeClient(function(id, done) {
 *       Client.findById(id, function (err, client) {
 *         done(err, client);
 *       });
 *     });
 *
 * @api public
 */
Server.prototype.deserializeClient = function () {
  var ref = _asyncToGenerator(function* (fn) {
    if (typeof fn === 'function') {
      return this._deserializers.push(fn);
    }

    // private implementation that traverses the chain of deserializers,
    // attempting to deserialize a client
    var obj = fn;

    var stack = this._deserializers;

    for (var i = 0;; i++) {
      let layer = stack[i];
      if (!layer) {
        throw new Error('Failed to deserialize client. Register deserialization function using deserializeClient().');
      }

      let client = yield layer(obj);
      // a valid client existed when establishing the session, but that client has
      // since been deauthorized
      if (client === null || client === false) {
        return false;
      } else if (client) {
        return client;
      }
    }
  });

  return function (_x2) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Parse authorization request into transaction using registered grant middleware.
 *
 * @param {String} type
 * @param {http.ServerRequest} req
 * @param {Function} cb
 * @api private
 */
Server.prototype._parse = function () {
  var ref = _asyncToGenerator(function* (type, ctx) {
    var ultype = new UnorderedList(type),
        stack = this._reqParsers,
        areq = {};

    if (type) {
      areq.type = type;
    }

    for (var i = 0;; i++) {
      let layer = stack[i];
      if (!layer) {
        return areq;
      }
      debug('parse:%s', layer.handle.name || 'anonymous');
      if (layer.type === null || layer.type.equalTo(ultype)) {
        let o = yield layer.handle(ctx);
        utils.merge(areq, o);
      }
    }
  });

  return function (_x3, _x4) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Respond to authorization transaction using registered grant middleware.
 *
 * @param {Object} txn
 * @param {http.ServerResponse} res
 * @api private
 */
Server.prototype._respond = function (ctx, notHandled) {
  var ultype = new UnorderedList(ctx.state.oauth2.req.type);
  var stack = this._resHandlers.filter(function (layer) {
    return layer.type === null || layer.type.equalTo(ultype);
  }).map(layer => layer.handle);

  var composed = compose(stack);
  return composed(ctx, notHandled);
};

/**
 * Process token request using registered exchange middleware.
 *
 * @param {String} type
 * @param {http.ServerRequest} req
 * @param {http.ServerResponse} res
 * @param {Function} cb
 * @api private
 */
Server.prototype._exchange = function () {
  var ref = _asyncToGenerator(function* (type, ctx, notHandled) {
    var stack = this._exchanges.filter(function (layer) {
      return layer.type === null || layer.type === type;
    }).map(layer => layer.handle);

    var composed = compose(stack);
    return composed(ctx, notHandled);
  });

  return function (_x5, _x6, _x7) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Expose `Server`.
 */
exports = module.exports = Server;