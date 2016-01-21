/* global describe, it, expect, before */
/* jshint expr: true, sub: true */

var chai = require('chai')
  , Context = require('../context')
  , transactionLoader = require('../../lib/middleware/transactionLoader')
  , Server = require('../../lib/server');


describe('transactionLoader', function() {

  function next() {}

  var server = new Server();
  server.deserializeClient(function(id) {
    if (id === '1') { return { id: id, name: 'Test' }; }
    if (id === '2') { return false; }
    throw new Error('something went wrong while deserializing client');
  });

  it('should be named transactionLoader', function() {
    expect(transactionLoader(server).name).to.equal('transactionLoader');
  });

  it('should throw if constructed without a server argument', function() {
    expect(function() {
      transactionLoader();
    }).to.throw(TypeError, 'oauth2orize.transactionLoader middleware requires a server argument');
  });

  describe('handling a request with transaction id in query', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { 'transaction_id': '1234' };
      ctx.session = {};
      ctx.session.authorize = {};
      ctx.session.authorize['1234'] = {
        client: '1',
        redirectURI: 'http://www.example.com/auth/callback',
        req: { redirectURI: 'http://www.example.com/auth/callback', foo: 'bar' }
      };

      try{
        await transactionLoader(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should not error', function() {
      expect(err).to.be.undefined;
    });

    it('should restore transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
      expect(ctx.state.oauth2.transactionID).to.equal('1234');
      expect(ctx.state.oauth2.client.id).to.equal('1');
      expect(ctx.state.oauth2.client.name).to.equal('Test');
      expect(ctx.state.oauth2.redirectURI).to.equal('http://www.example.com/auth/callback');
      expect(ctx.state.oauth2.req.redirectURI).to.equal('http://www.example.com/auth/callback');
      expect(ctx.state.oauth2.req.foo).to.equal('bar');
    });

    it('should leave transaction in session', function() {
      expect(ctx.session['authorize']['1234']).to.be.an('object');
    });
  });

  describe('handling a request with transaction id in body', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.body = { 'transaction_id': '1234' };
      ctx.session = {};
      ctx.session.authorize = {};
      ctx.session.authorize['1234'] = {
        client: '1',
        redirectURI: 'http://www.example.com/auth/callback',
        req: { redirectURI: 'http://www.example.com/auth/callback', foo: 'bar' },
        info: { beep: 'boop' }
      };

      try{
        await transactionLoader(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should not error', function() {
      expect(err).to.be.undefined;
    });

    it('should restore transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
      expect(ctx.state.oauth2.transactionID).to.equal('1234');
      expect(ctx.state.oauth2.client.id).to.equal('1');
      expect(ctx.state.oauth2.client.name).to.equal('Test');
      expect(ctx.state.oauth2.redirectURI).to.equal('http://www.example.com/auth/callback');
      expect(ctx.state.oauth2.req.redirectURI).to.equal('http://www.example.com/auth/callback');
      expect(ctx.state.oauth2.req.foo).to.equal('bar');
      expect(ctx.state.oauth2.info.beep).to.equal('boop');
    });

    it('should leave transaction in session', function() {
      expect(ctx.session['authorize']['1234']).to.be.an('object');
    });
  });

  describe('handling a request initiated by deactivated client', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { 'transaction_id': '1234' };
      ctx.session = {};
      ctx.session.authorize = {};
      ctx.session.authorize['1234'] = {
        client: '2',
        redirectURI: 'http://www.example.com/auth/callback',
        req: { redirectURI: 'http://www.example.com/auth/callback', foo: 'bar' }
      };

      try{
        await transactionLoader(server)(ctx, next);
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

    it('should not restore transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });

    it('should remove transaction from session', function() {
      expect(ctx.session['authorize']['1234']).to.be.undefined;
    });
  });

  describe('encountering an error while deserializing client', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { 'transaction_id': '1234' };
      ctx.session = {};
      ctx.session.authorize = {};
      ctx.session.authorize['1234'] = {
        client: 'error',
        redirectURI: 'http://www.example.com/auth/callback',
        req: { redirectURI: 'http://www.example.com/auth/callback', foo: 'bar' }
      };

      try{
        await transactionLoader(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went wrong while deserializing client');
    });

    it('should not restore transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });

    it('should leave transaction in session', function() {
      expect(ctx.session['authorize']['1234']).to.be.an('object');
    });
  });

  describe('handling a request without transaction id', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.session = {};
      ctx.session.authorize = {};

      try{
        await transactionLoader(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('BadRequestError');
      expect(err.message).to.equal('Missing required parameter: transaction_id');
    });

    it('should not restore transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });
  });

  describe('handling a request with transaction id that does not reference transaction', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.body = { 'transaction_id': '1234' };
      ctx.session = {};
      ctx.session.authorize = {};

      try{
        await transactionLoader(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('ForbiddenError');
      expect(err.message).to.equal('Unable to load OAuth 2.0 transaction: 1234');
    });

    it('should not restore transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });
  });

  describe('handling a request without transactions in session', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.body = { 'transaction_id': '1234' };
      ctx.session = {};

      try{
        await transactionLoader(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('ForbiddenError');
      expect(err.message).to.equal('Unable to load OAuth 2.0 transactions from session');
    });

    it('should not restore transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });
  });

  describe('handling a request without a session', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();

      try{
        await transactionLoader(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('OAuth2orize requires session support. Did you forget app.use(express.session(...))?');
    });

    it('should not restore transaction', function() {
      expect(ctx.state.oauth2).to.be.undefined;
    });
  });

  describe('with transaction field option', function() {
    describe('handling a request with transaction id in body', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.body = { 'txn_id': '1234' };
        ctx.session = {};
        ctx.session.authorize = {};
        ctx.session.authorize['1234'] = {
          client: '1',
          redirectURI: 'http://www.example.com/auth/callback',
          req: { redirectURI: 'http://www.example.com/auth/callback', foo: 'bar' }
        };

        try{
          await transactionLoader(server, { transactionField: 'txn_id' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should restore transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.transactionID).to.equal('1234');
        expect(ctx.state.oauth2.client.id).to.equal('1');
        expect(ctx.state.oauth2.client.name).to.equal('Test');
        expect(ctx.state.oauth2.redirectURI).to.equal('http://www.example.com/auth/callback');
        expect(ctx.state.oauth2.req.redirectURI).to.equal('http://www.example.com/auth/callback');
        expect(ctx.state.oauth2.req.foo).to.equal('bar');
      });

      it('should leave transaction in session', function() {
        expect(ctx.session['authorize']['1234']).to.be.an('object');
      });
    });
  });

  describe('with session key option', function() {
    describe('handling a request with transaction id in body', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.body = { 'transaction_id': '1234' };
        ctx.session = {};
        ctx.session.oauth2orize = {};
        ctx.session.oauth2orize['1234'] = {
          client: '1',
          redirectURI: 'http://www.example.com/auth/callback',
          req: { redirectURI: 'http://www.example.com/auth/callback', foo: 'bar' }
        };

        try{
          await transactionLoader(server, { sessionKey: 'oauth2orize' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should restore transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.transactionID).to.equal('1234');
        expect(ctx.state.oauth2.client.id).to.equal('1');
        expect(ctx.state.oauth2.client.name).to.equal('Test');
        expect(ctx.state.oauth2.redirectURI).to.equal('http://www.example.com/auth/callback');
        expect(ctx.state.oauth2.req.redirectURI).to.equal('http://www.example.com/auth/callback');
        expect(ctx.state.oauth2.req.foo).to.equal('bar');
      });

      it('should leave transaction in session', function() {
        expect(ctx.session['oauth2orize']['1234']).to.be.an('object');
      });
    });
  });

});
