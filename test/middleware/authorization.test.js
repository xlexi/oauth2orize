/* global describe, it, expect, before */
/* jshint camelcase: false, expr: true, sub: true */

var chai = require('chai')
  , Context = require('../context')
  , authorization = require('../../lib/middleware/authorization')
  , Server = require('../../lib/server');


describe('authorization', function() {

  var server = new Server();
  server.serializeClient(function(client) {
    if (client.id == '1234' || client.id == '2234' || client.id == '3234') { return client.id; }
    throw new Error('something went wrong while serializing client');
  });

  server.grant('code', function(ctx) {
    return {
      clientID: ctx.query['client_id'],
      redirectURI: ctx.query['redirect_uri'],
      scope: ctx.query['scope']
    };
  });

  server.grant('throw-error', function(ctx) {
    throw new Error('something went wrong while parsing authorization request');
  });

  function validate(clientID, redirectURI) {
    if (clientID == '1234' && redirectURI == 'http://example.com/auth/callback') {
      return [{ id: '1234', name: 'Example' }, 'http://example.com/auth/callback'];
    }
    if (clientID == '1235' && redirectURI == 'http://example.com/auth/callback') {
      return [{ id: '1235', name: 'Example' }, 'http://example.com/auth/callback'];
    }
    if (clientID == '2234') {
      return [false];
    }
    if (clientID == '3234') {
      return [false, 'http://example.com/auth/callback'];
    }
    if (clientID == '4234') {
      throw new Error('something was thrown while validating client');
    }
    throw new Error('something went wrong while validating client');
  }


  it('should be named authorization', function() {
    expect(authorization(server, function(){}).name).to.equal('authorization');
  });

  it('should throw if constructed without a server argument', function() {
    expect(function() {
      authorization();
    }).to.throw(TypeError, 'oauth2orize.authorization middleware requires a server argument');
  });

  it('should throw if constructed without a validate argument', function() {
    expect(function() {
      authorization(server);
    }).to.throw(TypeError, 'oauth2orize.authorization middleware requires a validate function');
  });

  describe('handling a request for authorization', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};

      try {
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should not error', function() {
      expect(err).to.be.undefined;
    });

    it('should add transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
      expect(ctx.state.oauth2.transactionID).to.be.a('string');
      expect(ctx.state.oauth2.transactionID).to.have.length(8);
      expect(ctx.state.oauth2.client.id).to.equal('1234');
      expect(ctx.state.oauth2.client.name).to.equal('Example');
      expect(ctx.state.oauth2.redirectURI).to.equal('http://example.com/auth/callback');
      expect(ctx.state.oauth2.req.type).to.equal('code');
      expect(ctx.state.oauth2.req.clientID).to.equal('1234');
      expect(ctx.state.oauth2.req.redirectURI).to.equal('http://example.com/auth/callback');
    });

    it('should store transaction in session', function() {
      var tid = ctx.state.oauth2.transactionID;
      expect(ctx.session['authorize'][tid]).to.be.an('object');
      expect(ctx.session['authorize'][tid].protocol).to.equal('oauth2');
      expect(ctx.session['authorize'][tid].client).to.equal('1234');
      expect(ctx.session['authorize'][tid].redirectURI).to.equal('http://example.com/auth/callback');
      expect(ctx.session['authorize'][tid].req.type).to.equal('code');
      expect(ctx.session['authorize'][tid].req.clientID).to.equal('1234');
      expect(ctx.session['authorize'][tid].req.redirectURI).to.equal('http://example.com/auth/callback');
    });
  });

  describe('handling a request for authorization with empty query', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.session = {};

      try{
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('AuthorizationError');
      expect(err.message).to.equal('Missing required parameter: response_type');
      expect(err.code).to.equal('invalid_request');
    });

    it('should not start transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });
  });

  describe('handling a request for authorization with unsupported response type', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'foo', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};

      try{
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('AuthorizationError');
      expect(err.message).to.equal('Unsupported response type: foo');
      expect(err.code).to.equal('unsupported_response_type');
    });

    it('should not start transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });
  });

  describe('handling a request for authorization from unauthorized client', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: '2234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};

      try{
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('AuthorizationError');
      expect(err.message).to.equal('Unauthorized client');
      expect(err.code).to.equal('unauthorized_client');
    });

    it('should start transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
      expect(ctx.state.oauth2.client).to.be.undefined;
      expect(ctx.state.oauth2.redirectURI).to.be.undefined;
    });
  });

  describe('handling a request for authorization from unauthorized client informed via redirect', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: '3234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};

      try{
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('AuthorizationError');
      expect(err.message).to.equal('Unauthorized client');
      expect(err.code).to.equal('unauthorized_client');
    });

    it('should start transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
      expect(ctx.state.oauth2.client).to.be.undefined;
      expect(ctx.state.oauth2.redirectURI).to.equal('http://example.com/auth/callback');
    });
  });

  describe('encountering an error thrown while parsing request', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'throw-error', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};

      try{
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went wrong while parsing authorization request');
    });

    it('should not start transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });
  });

  describe('encountering an error while validating client', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: '9234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};

      try{
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went wrong while validating client');
    });

    it('should start transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
      expect(ctx.state.oauth2.client).to.be.undefined;
      expect(ctx.state.oauth2.redirectURI).to.be.undefined;
    });
  });

  describe('encountering an error while serializing client', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: '1235', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};

      try{
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went wrong while serializing client');
    });

    it('should start transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
      expect(ctx.state.oauth2.client.id).to.equal('1235');
      expect(ctx.state.oauth2.client.name).to.equal('Example');
      expect(ctx.state.oauth2.redirectURI).to.equal('http://example.com/auth/callback');
      expect(ctx.state.oauth2.req).to.be.an('object');
      expect(ctx.state.oauth2.req.type).to.equal('code');
      expect(ctx.state.oauth2.req.clientID).to.equal('1235');
      expect(ctx.state.oauth2.req.redirectURI).to.equal('http://example.com/auth/callback');
    });
  });

  describe('handling a request for authorization without a session', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };

      try{
        await authorization(server, validate)(ctx);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('OAuth2orize requires session support. Did you forget app.use(express.session(...))?');
    });

    it('should not start transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });
  });

  describe('validate with scope', function() {
    function validate(clientID, redirectURI, scope) {
      if (clientID == '1234' && redirectURI == 'http://example.com/auth/callback' && scope == 'write') {
        return [{ id: '1234', name: 'Example' }, 'http://example.com/auth/callback'];
      }
      throw new Error('something went wrong while validating client');
    }

    describe('handling a request for authorization', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback', scope: 'write' };
        ctx.session = {};

        try{
          await authorization(server, validate)(ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.transactionID).to.be.a('string');
        expect(ctx.state.oauth2.transactionID).to.have.length(8);
        expect(ctx.state.oauth2.client.id).to.equal('1234');
        expect(ctx.state.oauth2.client.name).to.equal('Example');
        expect(ctx.state.oauth2.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.state.oauth2.req.type).to.equal('code');
        expect(ctx.state.oauth2.req.clientID).to.equal('1234');
        expect(ctx.state.oauth2.req.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.state.oauth2.req.scope).to.equal('write');
      });

      it('should store transaction in session', function() {
        var tid = ctx.state.oauth2.transactionID;
        expect(ctx.session['authorize'][tid]).to.be.an('object');
        expect(ctx.session['authorize'][tid].protocol).to.equal('oauth2');
        expect(ctx.session['authorize'][tid].client).to.equal('1234');
        expect(ctx.session['authorize'][tid].redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.session['authorize'][tid].req.type).to.equal('code');
        expect(ctx.session['authorize'][tid].req.clientID).to.equal('1234');
        expect(ctx.session['authorize'][tid].req.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.session['authorize'][tid].req.scope).to.equal('write');
      });
    });
  });

  describe('validate with scope and type', function() {
    function validate(clientID, redirectURI, scope, type) {
      if (clientID == '1234' && redirectURI == 'http://example.com/auth/callback' && scope == 'write' && type == 'code') {
        return [{ id: '1234', name: 'Example' }, 'http://example.com/auth/callback'];
      }
      throw new Error('something went wrong while validating client');
    }

    describe('handling a request for authorization', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback', scope: 'write' };
        ctx.session = {};

        try{
          await authorization(server, validate)(ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.transactionID).to.be.a('string');
        expect(ctx.state.oauth2.transactionID).to.have.length(8);
        expect(ctx.state.oauth2.client.id).to.equal('1234');
        expect(ctx.state.oauth2.client.name).to.equal('Example');
        expect(ctx.state.oauth2.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.state.oauth2.req.type).to.equal('code');
        expect(ctx.state.oauth2.req.clientID).to.equal('1234');
        expect(ctx.state.oauth2.req.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.state.oauth2.req.scope).to.equal('write');
      });

      it('should store transaction in session', function() {
        var tid = ctx.state.oauth2.transactionID;
        expect(ctx.session['authorize'][tid]).to.be.an('object');
        expect(ctx.session['authorize'][tid].protocol).to.equal('oauth2');
        expect(ctx.session['authorize'][tid].client).to.equal('1234');
        expect(ctx.session['authorize'][tid].redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.session['authorize'][tid].req.type).to.equal('code');
        expect(ctx.session['authorize'][tid].req.clientID).to.equal('1234');
        expect(ctx.session['authorize'][tid].req.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.session['authorize'][tid].req.scope).to.equal('write');
      });
    });
  });

  describe('validate with authorization request', function() {
    function validate(areq) {
      if (areq.clientID == '1234' && areq.redirectURI == 'http://example.com/auth/callback') {
        return [{ id: '1234', name: 'Example' }, 'http://example.com/auth/callback'];
      }
      throw new Error('something went wrong while validating client');
    }

    describe('handling a request for authorization', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
        ctx.session = {};

        try{
          await authorization(server, validate)(ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.transactionID).to.be.a('string');
        expect(ctx.state.oauth2.transactionID).to.have.length(8);
        expect(ctx.state.oauth2.client.id).to.equal('1234');
        expect(ctx.state.oauth2.client.name).to.equal('Example');
        expect(ctx.state.oauth2.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.state.oauth2.req.type).to.equal('code');
        expect(ctx.state.oauth2.req.clientID).to.equal('1234');
        expect(ctx.state.oauth2.req.redirectURI).to.equal('http://example.com/auth/callback');
      });

      it('should store transaction in session', function() {
        var tid = ctx.state.oauth2.transactionID;
        expect(ctx.session['authorize'][tid]).to.be.an('object');
        expect(ctx.session['authorize'][tid].protocol).to.equal('oauth2');
        expect(ctx.session['authorize'][tid].client).to.equal('1234');
        expect(ctx.session['authorize'][tid].redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.session['authorize'][tid].req.type).to.equal('code');
        expect(ctx.session['authorize'][tid].req.clientID).to.equal('1234');
        expect(ctx.session['authorize'][tid].req.redirectURI).to.equal('http://example.com/auth/callback');
      });
    });
  });

  describe('with id length option', function() {
    describe('handling a request for authorization', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
        ctx.session = {};

        try{
          await authorization(server, { idLength: 12 }, validate)(ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.transactionID).to.be.a('string');
        expect(ctx.state.oauth2.transactionID).to.have.length(12);
        expect(ctx.state.oauth2.client.id).to.equal('1234');
        expect(ctx.state.oauth2.client.name).to.equal('Example');
        expect(ctx.state.oauth2.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.state.oauth2.req.type).to.equal('code');
        expect(ctx.state.oauth2.req.clientID).to.equal('1234');
        expect(ctx.state.oauth2.req.redirectURI).to.equal('http://example.com/auth/callback');
      });

      it('should store transaction in session', function() {
        var tid = ctx.state.oauth2.transactionID;
        expect(ctx.session['authorize'][tid]).to.be.an('object');
        expect(ctx.session['authorize'][tid].protocol).to.equal('oauth2');
        expect(ctx.session['authorize'][tid].client).to.equal('1234');
        expect(ctx.session['authorize'][tid].redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.session['authorize'][tid].req.type).to.equal('code');
        expect(ctx.session['authorize'][tid].req.clientID).to.equal('1234');
        expect(ctx.session['authorize'][tid].req.redirectURI).to.equal('http://example.com/auth/callback');
      });
    });
  });

  describe('with session key option', function() {
    describe('handling a request for authorization', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
        ctx.session = {};

        try{
          await authorization(server, { sessionKey: 'oauth2z' }, validate)(ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.transactionID).to.be.a('string');
        expect(ctx.state.oauth2.transactionID).to.have.length(8);
        expect(ctx.state.oauth2.client.id).to.equal('1234');
        expect(ctx.state.oauth2.client.name).to.equal('Example');
        expect(ctx.state.oauth2.redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.state.oauth2.req.type).to.equal('code');
        expect(ctx.state.oauth2.req.clientID).to.equal('1234');
        expect(ctx.state.oauth2.req.redirectURI).to.equal('http://example.com/auth/callback');
      });

      it('should store transaction in session', function() {
        var tid = ctx.state.oauth2.transactionID;
        expect(ctx.session['oauth2z'][tid]).to.be.an('object');
        expect(ctx.session['oauth2z'][tid].protocol).to.equal('oauth2');
        expect(ctx.session['oauth2z'][tid].client).to.equal('1234');
        expect(ctx.session['oauth2z'][tid].redirectURI).to.equal('http://example.com/auth/callback');
        expect(ctx.session['oauth2z'][tid].req.type).to.equal('code');
        expect(ctx.session['oauth2z'][tid].req.clientID).to.equal('1234');
        expect(ctx.session['oauth2z'][tid].req.redirectURI).to.equal('http://example.com/auth/callback');
      });
    });
  });

  describe('server without registered grants', function() {
    var server = new Server();
    server.serializeClient(function(client) {
      return client.id;
    });

    function validate(clientID, redirectURI) {
      if (clientID == '1234' && redirectURI == 'http://example.com/auth/callback') {
        return [{ id: '1234', name: 'Example' }, 'http://example.com/auth/callback'];
      }
      throw new Error('something went wrong while validating client');
    }

    describe('handling a request for authorization', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
        ctx.session = {};

        try{
          await authorization(server, validate)(ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Unsupported response type: code');
        expect(err.code).to.equal('unsupported_response_type');
      });

      it('should not start transaction', function() {
        expect(ctx.state.oauth2).to.be.undefined;
      });
    });
  });

});
