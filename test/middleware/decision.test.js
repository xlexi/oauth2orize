/* global describe, it, expect, before */
/* jshint expr: true, sub: true */

var chai = require('chai')
  , Context = require('../context')
  , decision = require('../../lib/middleware/decision')
  , Server = require('../../lib/server');


describe('decision', function() {
  function next() {}
  var server = new Server();
  server.grant('code', 'response', function(ctx) {
    var txn = ctx.state.oauth2;
    if (txn.res.allow === false) { return ctx.redirect(txn.redirectURI + '?error=access_denied'); }
    if (txn.transactionID == 'abc123') { return ctx.redirect(txn.redirectURI + '?code=a1b1c1'); }
    throw new Error('something went wrong while handling response');
  });

  it('should be named decision', function() {
    expect(decision(server).name).to.equal('decision');
  });

  it('should throw if constructed without a server argument', function() {
    expect(function() {
      decision();
    }).to.throw(TypeError, 'oauth2orize.decision middleware requires a server argument');
  });

  describe('handling a user decision to allow access', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.request.body = {};
      ctx.session = {};
      ctx.session['authorize'] = {};
      ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
      ctx.state.user = { id: 'u1234', username: 'bob' };
      ctx.state.oauth2 = {};
      ctx.state.oauth2.transactionID = 'abc123';
      ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
      ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
      ctx.state.oauth2.req = { type: 'code', scope: 'email' };

      try{
        await decision(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should set user on transaction', function() {
      expect(ctx.state.oauth2.user).to.be.an('object');
      expect(ctx.state.oauth2.user.id).to.equal('u1234');
      expect(ctx.state.oauth2.user.username).to.equal('bob');
    });

    it('should set response on transaction', function() {
      expect(ctx.state.oauth2.res).to.be.an('object');
      expect(ctx.state.oauth2.res.allow).to.be.true;
    });

    it('should respond', function() {
      expect(ctx.status).to.equal(302);
      expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?code=a1b1c1');
    });

    it('should remove transaction from session', function() {
      expect(ctx.session['authorize']['abc123']).to.be.undefined;
    });
  });

  describe('handling a user decision to deny access', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.request.body = { cancel: 'Deny' };
      ctx.session = {};
      ctx.session['authorize'] = {};
      ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
      ctx.state.user = { id: 'u1234', username: 'bob' };
      ctx.state.oauth2 = {};
      ctx.state.oauth2.transactionID = 'abc123';
      ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
      ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
      ctx.state.oauth2.req = { type: 'code', scope: 'email' };

      try{
        await decision(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should set user on transaction', function() {
      expect(ctx.state.oauth2.user).to.be.an('object');
      expect(ctx.state.oauth2.user.id).to.equal('u1234');
      expect(ctx.state.oauth2.user.username).to.equal('bob');
    });

    it('should set response on transaction', function() {
      expect(ctx.state.oauth2.res).to.be.an('object');
      expect(ctx.state.oauth2.res.allow).to.be.false;
    });

    it('should respond', function() {
      expect(ctx.status).to.equal(302);
      expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?error=access_denied');
    });

    it('should remove transaction from session', function() {
      expect(ctx.session['authorize']['abc123']).to.be.undefined;
    });
  });

  describe('handling a user decision to allow access using unknown response type', function() {
    var ctx, err, resolve;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.request.body = {};
      ctx.session = {};
      ctx.session['authorize'] = {};
      ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
      ctx.state.user = { id: 'u1234', username: 'bob' };
      ctx.state.oauth2 = {};
      ctx.state.oauth2.transactionID = 'abc123';
      ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
      ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
      ctx.state.oauth2.req = { type: 'foo', scope: 'email' };

      try{
        await decision(server)(ctx, next);
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

    it('should set user on transaction', function() {
      expect(ctx.state.oauth2.user).to.be.an('object');
      expect(ctx.state.oauth2.user.id).to.equal('u1234');
      expect(ctx.state.oauth2.user.username).to.equal('bob');
    });

    it('should set response on transaction', function() {
      expect(ctx.state.oauth2.res).to.be.an('object');
      expect(ctx.state.oauth2.res.allow).to.be.true;
    });

    it('should remove the transaction from the session', function() {
      expect(ctx.session['authorize']['abc123']).to.be.undefined;
    });
  });

  describe('encountering an error while responding with grant', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.request.body = {};
      ctx.session = {};
      ctx.session['authorize'] = {};
      ctx.session['authorize']['err123'] = { protocol: 'oauth2' };
      ctx.state.user = { id: 'u1234', username: 'bob' };
      ctx.state.oauth2 = {};
      ctx.state.oauth2.transactionID = 'err123';
      ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
      ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
      ctx.state.oauth2.req = { type: 'code', scope: 'email' };

      try{
        await decision(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went wrong while handling response');
    });

    it('should set user on transaction', function() {
      expect(ctx.state.oauth2.user).to.be.an('object');
      expect(ctx.state.oauth2.user.id).to.equal('u1234');
      expect(ctx.state.oauth2.user.username).to.equal('bob');
    });

    it('should set response on transaction', function() {
      expect(ctx.state.oauth2.res).to.be.an('object');
      expect(ctx.state.oauth2.res.allow).to.be.true;
    });

    it('should remove the transaction from the session', function() {
      expect(ctx.session['authorize']['abc123']).to.be.undefined;
    });
  });

  describe('handling a request without a session', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.request.body = {};
      ctx.state.user = { id: 'u1234', username: 'bob' };
      ctx.state.oauth2 = {};
      ctx.state.oauth2.transactionID = 'abc123';
      ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
      ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
      ctx.state.oauth2.req = { type: 'code', scope: 'email' };

      try{
        await decision(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('OAuth2orize requires session support. Did you forget app.use(express.session(...))?');
    });

    it('should not set user on transaction', function() {
      expect(ctx.state.oauth2.user).to.be.undefined;
    });

    it('should not set response on transaction', function() {
      expect(ctx.state.oauth2.res).to.be.undefined;
    });
  });

  describe('handling a request without a body', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.session = {};
      ctx.session['authorize'] = {};
      ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
      ctx.state.user = { id: 'u1234', username: 'bob' };
      ctx.state.oauth2 = {};
      ctx.state.oauth2.transactionID = 'abc123';
      ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
      ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
      ctx.state.oauth2.req = { type: 'code', scope: 'email' };

      try{
        await decision(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?');
    });

    it('should not set user on transaction', function() {
      expect(ctx.state.oauth2.user).to.be.undefined;
    });

    it('should not set response on transaction', function() {
      expect(ctx.state.oauth2.res).to.be.undefined;
    });

    it('should leave transaction in session', function() {
      expect(ctx.session['authorize']['abc123']).to.be.an('object');
    });
  });

  describe('handling a request without a transaction', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.request.body = {};
      ctx.session = {};
      ctx.session['authorize'] = {};
      ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
      ctx.state.user = { id: 'u1234', username: 'bob' };

      try{
        await decision(server)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('OAuth2orize requires transaction support. Did you forget oauth2orize.transactionLoader(...)?');
    });

    it('should leave transaction in session', function() {
      expect(ctx.session['authorize']['abc123']).to.be.an('object');
    });
  });

  describe('handling a request without transactions in session', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = {};
      ctx.request.body = {};
      ctx.session = {};
      ctx.state.user = { id: 'u1234', username: 'bob' };
      ctx.state.oauth2 = {};
      ctx.state.oauth2.transactionID = 'abc123';
      ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
      ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
      ctx.state.oauth2.req = { type: 'code', scope: 'email' };

      try{
        await decision(server)(ctx, next);
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

    it('should not set user on transaction', function() {
      expect(ctx.state.oauth2.user).to.be.undefined;
    });

    it('should not set response on transaction', function() {
      expect(ctx.state.oauth2.res).to.be.undefined;
    });
  });

  describe('with parsing function', function() {
    var mw = decision(server, function(ctx) {
      return { scope: ctx.request.query.scope };
    });

    describe('handling a user decision', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.scope = 'no-email';
        ctx.request.body = {};
        ctx.session = {};
        ctx.session['authorize'] = {};
        ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
        ctx.state.user = { id: 'u1234', username: 'bob' };
        ctx.state.oauth2 = {};
        ctx.state.oauth2.transactionID = 'abc123';
        ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
        ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
        ctx.state.oauth2.req = { type: 'code', scope: 'email' };

        try{
          await mw(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set user on transaction', function() {
        expect(ctx.state.oauth2.user).to.be.an('object');
        expect(ctx.state.oauth2.user.id).to.equal('u1234');
        expect(ctx.state.oauth2.user.username).to.equal('bob');
      });

      it('should set response on transaction', function() {
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.be.true;
        expect(ctx.state.oauth2.res.scope).to.equal('no-email');
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?code=a1b1c1');
      });

      it('should remove transaction from session', function() {
        expect(ctx.session['authorize']['abc123']).to.be.undefined;
      });
    });
  });

  describe('with parsing function that denies access', function() {
    var mw = decision(server, function(ctx) {
      return { allow: false };
    });

    describe('handling a user decision', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.scope = 'no-email';
        ctx.request.body = {};
        ctx.session = {};
        ctx.session['authorize'] = {};
        ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
        ctx.state.user = { id: 'u1234', username: 'bob' };
        ctx.state.oauth2 = {};
        ctx.state.oauth2.transactionID = 'abc123';
        ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
        ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
        ctx.state.oauth2.req = { type: 'code', scope: 'email' };

        try{
          await mw(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set user on transaction', function() {
        expect(ctx.state.oauth2.user).to.be.an('object');
        expect(ctx.state.oauth2.user.id).to.equal('u1234');
        expect(ctx.state.oauth2.user.username).to.equal('bob');
      });

      it('should set response on transaction', function() {
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.be.false;
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?error=access_denied');
      });

      it('should remove transaction from session', function() {
        expect(ctx.session['authorize']['abc123']).to.be.undefined;
      });
    });
  });

  describe('with parsing function that errors', function() {
    var mw = decision(server, function(ctx) {
      throw new Error('something went wrong');
    });

    describe('handling a user decision', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = {};
        ctx.request.body = {};
        ctx.session = {};
        ctx.session['authorize'] = {};
        ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
        ctx.state.user = { id: 'u1234', username: 'bob' };
        ctx.state.oauth2 = {};
        ctx.state.oauth2.transactionID = 'abc123';
        ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
        ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
        ctx.state.oauth2.req = { type: 'code', scope: 'email' };

        try{
          await mw(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });

      it('should not set user on transaction', function() {
        expect(ctx.state.oauth2.user).to.be.undefined;
      });

      it('should not set response on transaction', function() {
        expect(ctx.state.oauth2.res).to.be.undefined;
      });

      it('should leave transaction in session', function() {
        expect(ctx.session['authorize']['abc123']).to.be.an('object');
      });
    });
  });

  describe('with parsing function that clears session', function() {
    var mw = decision(server, function(ctx) {
      ctx.session = {};
      return { scope: ctx.request.query.scope };
    });

    describe('handling a user decision', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.scope = 'no-email';
        ctx.request.body = {};
        ctx.session = {};
        ctx.session['authorize'] = {};
        ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
        ctx.state.user = { id: 'u1234', username: 'bob' };
        ctx.state.oauth2 = {};
        ctx.state.oauth2.transactionID = 'abc123';
        ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
        ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
        ctx.state.oauth2.req = { type: 'code', scope: 'email' };

        try{
          await mw(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set user on transaction', function() {
        expect(ctx.state.oauth2.user).to.be.an('object');
        expect(ctx.state.oauth2.user.id).to.equal('u1234');
        expect(ctx.state.oauth2.user.username).to.equal('bob');
      });

      it('should set response on transaction', function() {
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.be.true;
        expect(ctx.state.oauth2.res.scope).to.equal('no-email');
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?code=a1b1c1');
      });

      it('should remain a cleared session', function() {
        expect(Object.keys(ctx.session).length).to.equal(0);
      });
    });
  });

  describe('with cancel field option', function() {
    var mw = decision(server, { cancelField: 'deny' });

    describe('handling a user decision to deny access', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = {};
        ctx.request.body = { deny: 'Deny' };
        ctx.session = {};
        ctx.session['authorize'] = {};
        ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
        ctx.state.user = { id: 'u1234', username: 'bob' };
        ctx.state.oauth2 = {};
        ctx.state.oauth2.transactionID = 'abc123';
        ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
        ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
        ctx.state.oauth2.req = { type: 'code', scope: 'email' };

        try{
          await mw(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set user on transaction', function() {
        expect(ctx.state.oauth2.user).to.be.an('object');
        expect(ctx.state.oauth2.user.id).to.equal('u1234');
        expect(ctx.state.oauth2.user.username).to.equal('bob');
      });

      it('should set response on transaction', function() {
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.be.false;
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?error=access_denied');
      });

      it('should remove transaction from session', function() {
        expect(ctx.session['authorize']['abc123']).to.be.undefined;
      });
    });
  });

  describe('with session key option', function() {
    var mw = decision(server, { sessionKey: 'oauth2orize' });


    describe('handling a user decision to allow access', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = {};
        ctx.request.body = {};
        ctx.session = {};
        ctx.session['oauth2orize'] = {};
        ctx.session['oauth2orize']['abc123'] = { protocol: 'oauth2' };
        ctx.state.user = { id: 'u1234', username: 'bob' };
        ctx.state.oauth2 = {};
        ctx.state.oauth2.transactionID = 'abc123';
        ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
        ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
        ctx.state.oauth2.req = { type: 'code', scope: 'email' };

        try{
          await mw(ctx, next);
        } catch(e) {
          console.error(e.stack)
          err = e;
        }

        done();
      });

      it('should set user on transaction', function() {
        expect(ctx.state.oauth2.user).to.be.an('object');
        expect(ctx.state.oauth2.user.id).to.equal('u1234');
        expect(ctx.state.oauth2.user.username).to.equal('bob');
      });

      it('should set response on transaction', function() {
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.be.true;
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?code=a1b1c1');
      });

      it('should remove transaction from session', function() {
        expect(ctx.session['oauth2orize']['abc123']).to.be.undefined;
      });
    });
  });

  describe('with user property option', function() {
    var mw = decision(server, { userProperty: 'other' });

    describe('handling a user decision to allow access', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = {};
        ctx.request.body = {};
        ctx.session = {};
        ctx.session['authorize'] = {};
        ctx.session['authorize']['abc123'] = { protocol: 'oauth2' };
        ctx.state.other = { id: 'u1234', username: 'bob' };
        ctx.state.oauth2 = {};
        ctx.state.oauth2.transactionID = 'abc123';
        ctx.state.oauth2.client = { id: 'c5678', name: 'Example' };
        ctx.state.oauth2.redirectURI = 'http://example.com/auth/callback';
        ctx.state.oauth2.req = { type: 'code', scope: 'email' };

        try{
          await mw(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set user on transaction', function() {
        expect(ctx.state.oauth2.user).to.be.an('object');
        expect(ctx.state.oauth2.user.id).to.equal('u1234');
        expect(ctx.state.oauth2.user.username).to.equal('bob');
      });

      it('should set response on transaction', function() {
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.be.true;
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?code=a1b1c1');
      });

      it('should remove transaction from session', function() {
        expect(ctx.session['authorize']['abc123']).to.be.undefined;
      });
    });
  });

});
