'use strict';

var chai = require('chai')
  , Context = require('../context')
  , authorizationCode = require('../../lib/exchange/authorizationCode');


describe('exchange.authorizationCode', function() {

  function issue(client, code, redirectURI) {
    if (client.id == 'c123' && code == 'abc123' && redirectURI == 'http://example.com/oa/callback') {
      return  ['s3cr1t'];
    } else if (client.id == 'c223' && code == 'abc223' && redirectURI == 'http://example.com/oa/callback') {
      return  ['s3cr1t', 'getANotehr'];
    } else if (client.id == 'c323' && code == 'abc323' && redirectURI == 'http://example.com/oa/callback') {
      return  ['s3cr1t', null, { 'expires_in': 3600 }];
    } else if (client.id == 'c423' && code == 'abc423' && redirectURI == 'http://example.com/oa/callback') {
      return  ['s3cr1t', 'blahblag', { 'token_type': 'foo', 'expires_in': 3600 }];
    } else if (client.id == 'c523' && code == 'abc523' && redirectURI == 'http://example.com/oa/callback') {
      return  ['s3cr1t', { 'expires_in': 3600 }];
    } else if (client.id == 'cUN' && code == 'abcUN' && redirectURI == 'http://example.com/oa/callback') {
      return  [false];
    } else if (client.id == 'cTHROW') {
      throw new Error('something was thrown');
    }
    throw new Error('something is wrong');
  }

  it('should be named authorization_code', function() {
    expect(authorizationCode(function(){}).name).to.equal('authorization_code');
  });

  it('should throw if constructed without a issue callback', function() {
    expect(function() {
      authorizationCode();
    }).to.throw(TypeError, 'oauth2orize.authorizationCode exchange requires an issue callback');
  });

  describe('issuing an access token', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c123', name: 'Example' };
      ctx.request.body = { code: 'abc123', redirect_uri: 'http://example.com/oa/callback' }

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should respond with headers', function() {
      expect(ctx.response.get('Content-Type')).to.equal('application/json');
      expect(ctx.response.get('Cache-Control')).to.equal('no-store');
      expect(ctx.response.get('Pragma')).to.equal('no-cache');
    });

    it('should respond with body', function() {
      expect(ctx.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });

  describe('issuing an access token and refresh token', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c223', name: 'Example' };
      ctx.request.body = { code: 'abc223', redirect_uri: 'http://example.com/oa/callback' }

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should respond with headers', function() {
      expect(ctx.response.get('Content-Type')).to.equal('application/json');
      expect(ctx.response.get('Cache-Control')).to.equal('no-store');
      expect(ctx.response.get('Pragma')).to.equal('no-cache');
    });

    it('should respond with body', function() {
      expect(ctx.body).to.equal('{"access_token":"s3cr1t","refresh_token":"getANotehr","token_type":"Bearer"}');
    });
  });

  describe('issuing an access token and params', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c523', name: 'Example' };
      ctx.request.body = { code: 'abc523', redirect_uri: 'http://example.com/oa/callback' }

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should respond with headers', function() {
      expect(ctx.response.get('Content-Type')).to.equal('application/json');
      expect(ctx.response.get('Cache-Control')).to.equal('no-store');
      expect(ctx.response.get('Pragma')).to.equal('no-cache');
    });

    it('should respond with body', function() {
      expect(ctx.body).to.equal('{"access_token":"s3cr1t","expires_in":3600,"token_type":"Bearer"}');
    });
  });

  describe('issuing an access token, null refresh token, and params', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c323', name: 'Example' };
      ctx.request.body = { code: 'abc323', redirect_uri: 'http://example.com/oa/callback' }

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should respond with headers', function() {
      expect(ctx.response.get('Content-Type')).to.equal('application/json');
      expect(ctx.response.get('Cache-Control')).to.equal('no-store');
      expect(ctx.response.get('Pragma')).to.equal('no-cache');
    });

    it('should respond with body', function() {
      expect(ctx.body).to.equal('{"access_token":"s3cr1t","expires_in":3600,"token_type":"Bearer"}');
    });
  });

  describe('issuing an access token, refresh token, and params with token_type', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c423', name: 'Example' };
      ctx.request.body = { code: 'abc423', redirect_uri: 'http://example.com/oa/callback' }

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();

    });

    it('should respond with headers', function() {
      expect(ctx.response.get('Content-Type')).to.equal('application/json');
      expect(ctx.response.get('Cache-Control')).to.equal('no-store');
      expect(ctx.response.get('Pragma')).to.equal('no-cache');
    });

    it('should respond with body', function() {
      expect(ctx.body).to.equal('{"access_token":"s3cr1t","refresh_token":"blahblag","token_type":"foo","expires_in":3600}');
    });
  });

  describe('issuing an access token based on body', function() {
    var ctx, err;

    async function issue(client, code, redirectURI, body) {
      if (client.id == 'c123' && code == 'abc123' && redirectURI == 'http://example.com/oa/callback' && body.code_verifier == 's3cr1t') {
        return ['s3cr1t'];
      }
      throw new Error('something is wrong');
    }

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c123', name: 'Example' };
      ctx.request.body = { code: 'abc123', redirect_uri: 'http://example.com/oa/callback', code_verifier: 's3cr1t' }

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should respond with headers', function() {
      expect(ctx.response.get('Content-Type')).to.equal('application/json');
      expect(ctx.response.get('Cache-Control')).to.equal('no-store');
      expect(ctx.response.get('Pragma')).to.equal('no-cache');
    });

    it('should respond with body', function() {
      expect(ctx.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });

  describe('not issuing an access token', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'cUN', name: 'Example' };
      ctx.request.body = { code: 'abcUN', redirect_uri: 'http://example.com/oa/callback' };

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Invalid authorization code');
      expect(err.code).to.equal('invalid_grant');
      expect(err.status).to.equal(403);
    });
  });

  describe('handling a request without code parameter', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c123', name: 'Example' };
      ctx.request.body = { redirect_uri: 'http://example.com/oa/callback' };

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Missing required parameter: code');
      expect(err.code).to.equal('invalid_request');
      expect(err.status).to.equal(400);
    });
  });

  describe('encountering an error while issuing an access token', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'cXXX', name: 'Example' };
      ctx.request.body = { code: 'abcXXX', redirect_uri: 'http://example.com/oa/callback' };

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();

    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something is wrong');
    });
  });

  describe('encountering an exception while issuing an access token', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'cTHROW', name: 'Example' };
      ctx.request.body = { code: 'abc123', redirect_uri: 'http://example.com/oa/callback' };

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something was thrown');
    });
  });

  describe('handling a request without a body', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'cUN', name: 'Example' };

      try {
        await authorizationCode(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?');
    });
  });

  describe('with user property option issuing an access token', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.client = { id: 'c123', name: 'Example' };
      ctx.request.body = { code: 'abc123', redirect_uri: 'http://example.com/oa/callback' };

      try {
        await authorizationCode({ userProperty: 'client' }, issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should respond with headers', function() {
      expect(ctx.response.get('Content-Type')).to.equal('application/json');
      expect(ctx.response.get('Cache-Control')).to.equal('no-store');
      expect(ctx.response.get('Pragma')).to.equal('no-cache');
    });

    it('should respond with body', function() {
      expect(ctx.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });

});
