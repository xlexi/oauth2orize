/* global describe, it, expect, before */
/* jshint camelcase: false, expr: true, sub: true */

var chai = require('chai')
  , Context = require('../context')
  , authorization = require('../../lib/middleware/authorization')
  , Server = require('../../lib/server');


describe('authorization', function() {

  function next() {}
  var server = new Server();
  server.serializeClient(function(client) {
    return client.id;
  });

  server.grant('code', function(ctx) {
    return {
      clientID: ctx.query['client_id'],
      redirectURI: ctx.query['redirect_uri'],
      scope: ctx.query['scope']
    };
  });
  server.grant('code', 'response', function(ctx) {
    var txn = ctx.state.oauth2;
    if ((txn.client.id == '1234' || txn.client.id == '2234') && txn.user.id == 'u123' && txn.res.allow === true && txn.res.scope === 'read') {
      return ctx.redirect(txn.redirectURI);
    }
    throw new Error('something went wrong while sending response');
  });

  server.grant('foo', function(ctx) {
    return {
      clientID: ctx.query['client_id'],
      redirectURI: ctx.query['redirect_uri'],
      scope: ctx.query['scope']
    };
  });

  function validate(clientID, redirectURI) {
    return [{ id: clientID }, 'http://example.com/auth/callback'];
  }

  function immediate(client, user) {
    if (client.id == '1234' && user.id == 'u123') {
      return [true, { scope: 'read' }];
    } else if (client.id == '2234' && user.id == 'u123') {
      return [false];
    } else if (client.id == 'T234' && user.id == 'u123') {
      throw new Error('something was thrown while checking immediate status');
    } else if (client.id == 'ER34' && user.id == 'u123') {
      return [true, { scope: 'read' }];
    }
    throw new Error('something went wrong while checking immediate status');
  }

  describe('handling a request that is immediately authorized', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};
      ctx.state.user = { id: 'u123' };

      try{
        await authorization(server, validate, immediate)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should not error', function() {
      expect(err).to.be.undefined;
    });

    it('should respond', function() {
      expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback');
    });

    it('should add transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
    });

    it('should not store transaction in session', function() {
      expect(ctx.session['authorize']).to.be.undefined;
    });
  });

  describe('handling a request that is not immediately authorized', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: '2234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};
      ctx.state.user = { id: 'u123' };

      try{
        await authorization(server, validate, immediate)(ctx, next);
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
    });

    it('should store transaction in session', function() {
      var tid = ctx.state.oauth2.transactionID;
      expect(ctx.session['authorize'][tid]).to.be.an('object');
      expect(ctx.session['authorize'][tid].protocol).to.equal('oauth2');
      expect(ctx.session['authorize'][tid].client).to.equal('2234');
      expect(ctx.session['authorize'][tid].redirectURI).to.equal('http://example.com/auth/callback');
      expect(ctx.session['authorize'][tid].req.type).to.equal('code');
      expect(ctx.session['authorize'][tid].req.clientID).to.equal('2234');
      expect(ctx.session['authorize'][tid].req.redirectURI).to.equal('http://example.com/auth/callback');
    });
  });

  describe('handling a request that encounters an error while checking immediate status', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: 'X234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};
      ctx.state.user = { id: 'u123' };

      try{
        await authorization(server, validate, immediate)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went wrong while checking immediate status');
    });

    it('should add transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
    });

    it('should not store transaction in session', function() {
      expect(ctx.session['authorize']).to.be.undefined;
    });
  });

  describe('handling a request that throws an error while checking immediate status', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: 'T234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};
      ctx.state.user = { id: 'u123' };

      try{
        await authorization(server, validate, immediate)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something was thrown while checking immediate status');
    });

    it('should add transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
    });

    it('should not store transaction in session', function() {
      expect(ctx.session['authorize']).to.be.undefined;
    });
  });

  describe('handling a request that is immediately authorized but encounters an error while responding', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'code', client_id: 'ER34', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};
      ctx.state.user = { id: 'u123' };

      try{
        await authorization(server, validate, immediate)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went wrong while sending response');
    });

    it('should add transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
    });

    it('should not store transaction in session', function() {
      expect(ctx.session['authorize']).to.be.undefined;
    });
  });

  describe('handling a request that is immediately authorized but unable to respond', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.request.query = { response_type: 'foo', client_id: '1234', redirect_uri: 'http://example.com/auth/callback' };
      ctx.session = {};
      ctx.state.user = { id: 'u123' };

      try{
        await authorization(server, validate, immediate)(ctx, next);
      } catch(e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('Unsupported response type: foo');
    });

    it('should add transaction', function() {
      expect(ctx.state.oauth2).to.be.an('object');
    });

    it('should not store transaction in session', function() {
      expect(ctx.session['authorize']).to.be.undefined;
    });
  });

  describe('immediate callback with scope', function() {
    describe('handling a request that is immediately authorized', function() {
      var ctx, err;

      function immediate(client, user, scope) {
        if (client.id == '1234' && user.id == 'u123' && scope == 'profile') {
          return [true, { scope: 'read' }];
        }
        throw new Error('something went wrong while checking immediate status');
      }

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback', scope: 'profile' };
        ctx.session = {};
        ctx.state.user = { id: 'u123' };

        try{
          await authorization(server, validate, immediate)(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should respond', function() {
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback');
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.equal(true);
        expect(ctx.state.oauth2.res.scope).to.equal('read');
        expect(ctx.state.oauth2.info).to.be.undefined;
      });

      it('should not store transaction in session', function() {
        expect(ctx.session['authorize']).to.be.undefined;
      });
    });

    describe('handling a request that is not immediately authorized', function() {
      var ctx, err;

      function immediate(client, user, scope) {
        if (client.id == '1234' && user.id == 'u123' && scope == 'profile') {
          return [false, { scope: 'read', format: 'application/jwt' }];
        }
        throw new Error('something went wrong while checking immediate status');
      }

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback', scope: 'profile' };
        ctx.session = {};
        ctx.state.user = { id: 'u123' };

        try{
          await authorization(server, validate, immediate)(ctx, next);
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
        expect(ctx.state.oauth2.res).to.be.undefined;
        expect(ctx.state.oauth2.info).to.be.an('object');
        expect(ctx.state.oauth2.info.format).to.equal('application/jwt');
        expect(ctx.state.oauth2.info.scope).to.equal('read');
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
        expect(ctx.session['authorize'][tid].info.format).to.equal('application/jwt');
        expect(ctx.session['authorize'][tid].info.scope).to.equal('read');
      });
    });
  });

  describe('immediate callback with scope and locals', function() {
    describe('handling a request that is immediately authorized', function() {
      var ctx, err;

      function immediate(client, user, scope) {
        if (client.id == '1234' && user.id == 'u123' && scope == 'profile') {
          return [true, { scope: 'read' }, { beep: 'boop' }];
        }
        throw new Error('something went wrong while checking immediate status');
      }

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback', scope: 'profile' };
        ctx.session = {};
        ctx.state.user = { id: 'u123' };

        try{
          await authorization(server, validate, immediate)(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should respond', function() {
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback');
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.equal(true);
        expect(ctx.state.oauth2.res.scope).to.equal('read');
        expect(ctx.state.oauth2.info).to.be.undefined;
        expect(ctx.state.oauth2.locals).to.be.undefined;
      });

      it('should not store transaction in session', function() {
        expect(ctx.session['authorize']).to.be.undefined;
      });
    });

    describe('handling a request that is not immediately authorized', function() {
      var ctx, err;

      function immediate(client, user, scope) {
        if (client.id == '1234' && user.id == 'u123' && scope == 'profile') {
          return [false, { scope: 'read', format: 'application/jwt' }, { beep: 'boop' }];
        }
        throw new Error('something went wrong while checking immediate status');
      }

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback', scope: 'profile' };
        ctx.session = {};
        ctx.state.user = { id: 'u123' };

        try{
          await authorization(server, validate, immediate)(ctx, next);
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
        expect(ctx.state.oauth2.res).to.be.undefined;
        expect(ctx.state.oauth2.info).to.be.an('object');
        expect(ctx.state.oauth2.info.format).to.equal('application/jwt');
        expect(ctx.state.oauth2.info.scope).to.equal('read');
        expect(ctx.state.oauth2.locals).to.be.an('object');
        expect(ctx.state.oauth2.locals.beep).to.equal('boop');
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
        expect(ctx.session['authorize'][tid].info.format).to.equal('application/jwt');
        expect(ctx.session['authorize'][tid].info.scope).to.equal('read');
        expect(ctx.session['authorize'][tid].locals).to.be.undefined;
      });
    });
  });
('immediate callback with scope and type', function() {
    describe('handling a request that is immediately authorized', function() {
      var ctx, err;

      function immediate(client, user, scope, type) {
        if (client.id == '1234' && user.id == 'u123' && scope == 'profile' && type == 'code') {
          return [true, { scope: 'read' }];
        }
        throw new Error('something went wrong while checking immediate status');
      }

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback', scope: 'profile' };
        ctx.session = {};
        ctx.state.user = { id: 'u123' };

        try{
          await authorization(server, validate, immediate)(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should respond', function() {
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback');
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.equal(true);
        expect(ctx.state.oauth2.res.scope).to.equal('read');
        expect(ctx.state.oauth2.info).to.be.undefined;
      });

      it('should not store transaction in session', function() {
        expect(ctx.session['authorize']).to.be.undefined;
      });
    });
  });

  describe('immediate callback with scope and type and extensions', function() {
    describe('handling a request that is immediately authorized', function() {
      var ctx, err;

      var server = new Server();
      server.grant('code', function(ctx) {
        return {
          clientID: ctx.request.query['client_id'],
          redirectURI: ctx.request.query['redirect_uri'],
          scope: ctx.request.query['scope']
        };
      });

      server.grant('code', 'response', function(ctx) {
        var txn = ctx.state.oauth2;
        if ((txn.client.id == '1234' || txn.client.id == '2234') && txn.user.id == 'u123' && txn.res.allow === true && txn.res.scope === 'read') {
          return ctx.redirect(txn.redirectURI);
        }
        throw new Error('something went wrong while sending response');
      });

      server.grant('*', function(ctx) {
        return {
          audience: ctx.request.query['audience']
        };
      });

      function immediate(client, user, scope, type, ext) {
        if (client.id == '1234' && user.id == 'u123' && scope == 'profile' && type == 'code' && ext.audience == 'https://api.example.com/') {
          return [true, { scope: 'read' }];
        }
        throw new Error('something went wrong while checking immediate status');
      }

      before(async function(done) {
        ctx = new Context();
        ctx.request.query = { response_type: 'code', client_id: '1234', redirect_uri: 'http://example.com/auth/callback', scope: 'profile', audience: 'https://api.example.com/' };
        ctx.session = {};
        ctx.state.user = { id: 'u123' };

        try{
          await authorization(server, validate, immediate)(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should respond', function() {
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback');
      });

      it('should add transaction', function() {
        expect(ctx.state.oauth2).to.be.an('object');
        expect(ctx.state.oauth2.res).to.be.an('object');
        expect(ctx.state.oauth2.res.allow).to.equal(true);
        expect(ctx.state.oauth2.res.scope).to.equal('read');
        expect(ctx.state.oauth2.info).to.be.undefined;
      });

      it('should not store transaction in session', function() {
        expect(ctx.session['authorize']).to.be.undefined;
      });
    });
  });

});
