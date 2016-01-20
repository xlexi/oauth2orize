/* global describe, it, expect, before */
/* jshint expr: true */

var chai = require('chai')
  , Context = require('../context')
  , errorHandler = require('../../lib/middleware/errorHandler')
  , AuthorizationError = require('../../lib/errors/authorizationerror');


describe('errorHandler', function() {

  it('should be named errorHandler', function() {
    expect(errorHandler().name).to.equal('errorHandler');
  });

  describe('direct mode', function() {
    describe('handling an error', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler()(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(500);
        expect(ctx.response.get('Content-Type')).to.equal('application/json');
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should set response body', function() {
        expect(ctx.body).to.equal('{"error":"server_error","error_description":"something went wrong"}');
      });
    });

    describe('handling an authorization error', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();

        function next() { throw new AuthorizationError('something went wrong', 'invalid_request') }

        try{
          await errorHandler()(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(400);
        expect(ctx.response.get('Content-Type')).to.equal('application/json');
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should set response body', function() {
        expect(ctx.body).to.equal('{"error":"invalid_request","error_description":"something went wrong"}');
      });
    });

    describe('handling an authorization error with URI', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();

        function next() { throw new AuthorizationError('something went wrong', 'invalid_request', 'http://example.com/errors/1') }

        try{
          await errorHandler()(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(400);
        expect(ctx.response.get('Content-Type')).to.equal('application/json');
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should set response body', function() {
        expect(ctx.body).to.equal('{"error":"invalid_request","error_description":"something went wrong","error_uri":"http://example.com/errors/1"}');
      });
    });
  });

  describe('indirect mode', function() {
    describe('handling an error', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?error=server_error&error_description=something%20went%20wrong');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an authorization error', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };

        function next() { throw new AuthorizationError('not authorized', 'unauthorized_client') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?error=unauthorized_client&error_description=not%20authorized');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an authorization error with URI', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };

        function next() { throw new AuthorizationError('not authorized', 'unauthorized_client', 'http://example.com/errors/2') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?error=unauthorized_client&error_description=not%20authorized&error_uri=http%3A%2F%2Fexample.com%2Ferrors%2F2');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an error with state', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };
        ctx.state.oauth2.req = { state: '1234' };

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback?error=server_error&error_description=something%20went%20wrong&state=1234');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an error using token response', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };
        ctx.state.oauth2.req = { type: 'token' };

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=server_error&error_description=something%20went%20wrong');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an authorization error using token response', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };
        ctx.state.oauth2.req = { type: 'token' };

        function next() { throw new AuthorizationError('not authorized', 'unauthorized_client') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=unauthorized_client&error_description=not%20authorized');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an authorization error with URI using token response', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };
        ctx.state.oauth2.req = { type: 'token' };

        function next() { throw new AuthorizationError('not authorized', 'unauthorized_client', 'http://example.com/errors/2') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=unauthorized_client&error_description=not%20authorized&error_uri=http%3A%2F%2Fexample.com%2Ferrors%2F2');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an error with state using token response', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };
        ctx.state.oauth2.req = { type: 'token', state: '1234' };

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=server_error&error_description=something%20went%20wrong&state=1234');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an error using fragment encoding for extension response type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };
        ctx.state.oauth2.req = { type: 'code id_token' };

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect', fragment: ['token', 'id_token'] })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=server_error&error_description=something%20went%20wrong');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an error with state using custom response mode', function() {
      var customResponseMode = function(txn, res, params) {
        expect(txn.req.redirectURI).to.equal('http://example.com/auth/callback');
        expect(params.error).to.equal('server_error');
        expect(params.error_description).to.equal('something went wrong');
        expect(params.state).to.equal('1234');

        res.redirect('/custom');
      }

      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };
        ctx.state.oauth2.req = { type: 'token', redirectURI: 'http://example.com/auth/callback', state: '1234', responseMode: 'custom' };

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect', modes: { custom: customResponseMode } })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should set response headers', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('/custom');
        expect(ctx.response.get('Content-Type')).to.be.undefined;
        expect(ctx.response.get('WWW-Authenticate')).to.be.undefined;
      });

      it('should not set response body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling an error with state using unsupported response mode', function() {
      var customResponseMode = function(txn, res, params) {
        expect(txn.req.redirectURI).to.equal('http://example.com/auth/callback');
        expect(params.error).to.equal('server_error');
        expect(params.error_description).to.equal('something went wrong');
        expect(params.state).to.equal('1234');

        res.redirect('/custom');
      }

      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = { redirectURI: 'http://example.com/auth/callback' };
        ctx.state.oauth2.req = { type: 'token', redirectURI: 'http://example.com/auth/callback', state: '1234', responseMode: 'fubar' };

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect', modes: { custom: customResponseMode } })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should next with error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    });

    describe('handling a request error without an OAuth 2.0 transaction', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should next with error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    });

    describe('handling a request error without a redirect URI', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.oauth2 = {};

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'indirect' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should next with error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    });
  });

  describe('unknown mode', function() {
    describe('handling an error', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();

        function next() { throw new Error('something went wrong') }

        try{
          await errorHandler({ mode: 'unknown' })(ctx, next);
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should next with error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    });
  });

});
