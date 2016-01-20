/* global describe, it, expect, before */
/* jshint camelcase: false, expr: true */

var chai = require('chai')
  , Context = require('../context')
  , Server = require('../../lib/server')
  , token = require('../../lib/grant/token');


describe('grant.token', function() {

  describe('module', function() {
    var mod = token(function(){});

    it('should be named token', function() {
      expect(mod.name).to.equal('token');
    });

    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });

  it('should throw if constructed without a issue callback', function() {
    expect(function() {
      token();
    }).to.throw(TypeError, 'oauth2orize.token grant requires an issue callback');
  });

  describe('request parsing', function() {
    function issue(){}

    describe('request', function() {
      var err, out;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.state = 'f1o1o1';


        try{
          out = await server._parse('token', ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.undefined;
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with scope', function() {
      var err, out;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read';
        ctx.request.query.state = 'f1o1o1';


        try{
          out = await server._parse('token', ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(1);
        expect(out.scope[0]).to.equal('read');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with list of scopes', function() {
      var err, out;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read write';
        ctx.request.query.state = 'f1o1o1';


        try{
          out = await server._parse('token', ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with list of scopes using scope separator option', function() {
      var err, out;

      before(async function(done) {
        var server = new Server();
        server.grant(token({ scopeSeparator: ',' }, issue));

        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read,write';
        ctx.request.query.state = 'f1o1o1';


        try{
          out = await server._parse('token', ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with list of scopes separated by space using multiple scope separator option', function() {
      var err, out;

      before(async function(done) {
        var server = new Server();
        server.grant(token({ scopeSeparator: [' ', ','] }, issue));

        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read write';
        ctx.request.query.state = 'f1o1o1';


        try{
          out = await server._parse('token', ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with list of scopes separated by comma using multiple scope separator option', function() {
      var err, out;

      before(async function(done) {
        var server = new Server();
        server.grant(token({ scopeSeparator: [' ', ','] }, issue));

        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read,write';
        ctx.request.query.state = 'f1o1o1';


        try{
          out = await server._parse('token', ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with missing client_id parameter', function() {
      var err, out;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.state = 'f1o1o1';


        try{
          out = await server._parse('token', ctx);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Missing required parameter: client_id');
        expect(err.code).to.equal('invalid_request');
      });
    });
  });

  describe('decision handling', function() {
    function issue(client, user) {
      if (client.id == 'c123' && user.id == 'u123') {
        return ['xyz'];
      } else if (client.id == 'c223' && user.id == 'u123') {
        return ['xyz', { 'expires_in': 3600 }];
      } else if (client.id == 'c323' && user.id == 'u123') {
        return ['xyz', { 'token_type': 'foo', 'expires_in': 3600 }];
      } else if (client.id == 'cUNAUTHZ') {
        return [false];
      } else if (client.id == 'cTHROW') {
        throw new Error('something was thrown');
      }
      throw new Error('something is wrong');
    }

    describe('transaction', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer');
      });
    });

    describe('transaction with request state', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback',
          state: 'f1o1o1'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&state=f1o1o1');
      });
    });

    describe('transaction that adds params to response', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c223', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&expires_in=3600&token_type=Bearer');
      });
    });

    describe('transaction that adds params including token_type to response', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c323', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=foo&expires_in=3600');
      });
    });

    describe('disallowed transaction', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: false };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=access_denied');
      });
    });

    describe('disallowed transaction with request state', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback',
          state: 'f2o2o2'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: false };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=access_denied&state=f2o2o2');
      });
    });

    describe('unauthorized client', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'cUNAUTHZ', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Request denied by authorization server');
        expect(err.code).to.equal('access_denied');
        expect(err.status).to.equal(403);
      });
    });

    describe('encountering an error while issuing token', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'cERROR', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something is wrong');
      });
    });

    describe('throwing an error while issuing token', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'cTHROW', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something was thrown');
      });
    });

    describe('transaction without redirect URL', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('Unable to issue redirect for OAuth 2.0 transaction');
      });
    });
  });

  describe('decision handling with user response', function() {
    function issue(client, user, ares) {
      if (client.id == 'c123' && user.id == 'u123' && ares.scope == 'foo') {
        return ['xyz'];
      }
      throw new Error('something is wrong');
    }

    describe('transaction with response scope', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token(issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true, scope: 'foo' };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer');
      });
    });
  });

  describe('decision handling with response mode', function() {
    function issue(client, user) {
      if (client.id == 'c123' && user.id == 'u123') {
        return ['xyz'];
      }
      throw new Error('something is wrong');
    }

    var fooResponseMode = function(txn, res, params) {
      expect(txn.req.redirectURI).to.equal('http://example.com/auth/callback');
      expect(params.access_token).to.equal('xyz');
      expect(params.token_type).to.equal('Bearer');
      expect(params.state).to.equal('s1t2u3');

      res.redirect('/foo');
    }


    describe('transaction using default response mode', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token({ modes: { foo: fooResponseMode } }, issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback',
          state: 's1t2u3'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&state=s1t2u3');
      });
    });

    describe('transaction using foo response mode', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token({ modes: { foo: fooResponseMode } }, issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback',
          state: 's1t2u3',
          responseMode: 'foo'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('/foo');
      });
    });

    describe('disallowed transaction using foo response mode', function() {
      var fooResponseMode = function(txn, res, params) {
        expect(txn.req.redirectURI).to.equal('http://example.com/auth/callback');
        expect(params.error).to.equal('access_denied');
        expect(params.state).to.equal('s1t2u3');

        res.redirect('/foo');
      }

      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token({ modes: { foo: fooResponseMode } }, issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback',
          state: 's1t2u3',
          responseMode: 'foo'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: false };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('/foo');
      });
    });

    describe('transaction using unsupported response mode', function() {
      var ctx, err;

      before(async function(done) {
        var server = new Server();
        server.grant(token({ modes: { foo: fooResponseMode } }, issue));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {
          protocol: 'oauth2'
        };
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'token',
          redirectURI: 'http://example.com/auth/callback',
          state: 's1t2u3',
          responseMode: 'fubar'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };


        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Unsupported response mode: fubar');
        expect(err.code).to.equal('unsupported_response_mode');
        expect(err.uri).to.equal(null);
        expect(err.status).to.equal(501);
      });
    });
  });

});
