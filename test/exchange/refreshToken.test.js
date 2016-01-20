var chai = require('chai')
  , Context = require('../context')
  , refreshToken = require('../../lib/exchange/refreshToken');


describe('exchange.refreshToken', function() {

  function issue(client, refreshToken) {
    if (client.id == 'c123' && refreshToken == 'refreshing') {
      return ['s3cr1t'];
    } else if (client.id == 'c223' && refreshToken == 'refreshing') {
      return ['s3cr1t', 'getANotehr'];
    } else if (client.id == 'c323' && refreshToken == 'refreshing') {
      return ['s3cr1t', null, { 'expires_in': 3600 }];
    } else if (client.id == 'c423' && refreshToken == 'refreshing') {
      return ['s3cr1t', 'blahblag', { 'token_type': 'foo', 'expires_in': 3600 }];
    } else if (client.id == 'c523' && refreshToken == 'refreshing') {
      return ['s3cr1t', { 'expires_in': 3600 }];
    } else if (client.id == 'cUN' && refreshToken == 'refreshing') {
      return [false];
    } else if (client.id == 'cTHROW') {
      throw new Error('something was thrown')
    }
    throw new Error('something is wrong');
  }

  it('should be named refresh_token', function() {
    expect(refreshToken(function(){}).name).to.equal('refresh_token');
  });

  it('should throw if constructed without a issue callback', function() {
    expect(function() {
      refreshToken();
    }).to.throw(TypeError, 'oauth2orize.refreshToken exchange requires an issue callback');
  });

  describe('issuing an access token', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c123', name: 'Example' };
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken(issue)(ctx);
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
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken(issue)(ctx);
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
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken(issue)(ctx);
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
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken(issue)(ctx);
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
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken(issue)(ctx);
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

  describe('issuing an access token based on scope', function() {
    function issue(client, refreshToken, scope) {
      if (client.id == 'c123' && refreshToken == 'refreshing'
          && scope.length == 1 && scope[0] == 'read') {
        return ['s3cr1t'];
      }
      throw new Error('something is wrong');
    }

    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c123', name: 'Example' };
      ctx.request.body = { refresh_token: 'refreshing', scope: 'read' };

      try {
        await refreshToken(issue)(ctx);
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

  describe('issuing an access token based on array of scopes', function() {
    function issue(client, refreshToken, scope) {
      if (client.id == 'c123' && refreshToken == 'refreshing'
          && scope.length == 2 && scope[0] == 'read' && scope[1] == 'write') {
        return ['s3cr1t'];
      }
      throw new Error('something is wrong');
    }

    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c123', name: 'Example' };
      ctx.request.body = { refresh_token: 'refreshing', scope: 'read write' };

      try {
        await refreshToken(issue)(ctx);
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
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Invalid refresh token');
      expect(err.code).to.equal('invalid_grant');
      expect(err.status).to.equal(403);
    });
  });

  describe('handling a request without refresh token parameter', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'c123', name: 'Example' };
      ctx.request.body = {};

      try {
        await refreshToken(issue)(ctx);
      } catch (e) {
        err = e;
      }

      done();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Missing required parameter: refresh_token');
      expect(err.code).to.equal('invalid_request');
      expect(err.status).to.equal(400);
    });
  });

  describe('encountering an error while issuing an access token', function() {
    var ctx, err;

    before(async function(done) {
      ctx = new Context();
      ctx.state.user = { id: 'cXXX', name: 'Example' };
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken(issue)(ctx);
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
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken(issue)(ctx);
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
      ctx.state.user = { id: 'c123', name: 'Example' };

      try {
        await refreshToken(issue)(ctx);
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

  describe('with scope separator option', function() {
    describe('issuing an access token based on array of scopes', function() {
      function issue(client, refreshToken, scope) {
        if (client.id == 'c123' && refreshToken == 'refreshing'
            && scope.length == 2 && scope[0] == 'read' && scope[1] == 'write') {
          return ['s3cr1t'];
        }
        throw new Error('something is wrong');
      }

      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.user = { id: 'c123', name: 'Example' };
        ctx.request.body = { refresh_token: 'refreshing', scope: 'read,write' };

        try {
          await refreshToken({ scopeSeparator: ',' }, issue)(ctx);
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

  describe('with multiple scope separator option', function() {
    function issue(client, refreshToken, scope) {
      if (client.id == 'c123' && refreshToken == 'refreshing'
          && scope.length == 2 && scope[0] == 'read' && scope[1] == 'write') {
        return ['s3cr1t'];
      }
      throw new Error('something is wrong');
    }

    describe('issuing an access token based on scope separated by space', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.user = { id: 'c123', name: 'Example' };
        ctx.request.body = { refresh_token: 'refreshing', scope: 'read write' };

        try {
          await refreshToken({ scopeSeparator: [' ', ','] }, issue)(ctx);
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

    describe('issuing an access token based on scope separated by comma', function() {
      var ctx, err;

      before(async function(done) {
        ctx = new Context();
        ctx.state.user = { id: 'c123', name: 'Example' };
        ctx.request.body = { refresh_token: 'refreshing', scope: 'read,write' };

        try {
          await refreshToken({ scopeSeparator: [' ', ','] }, issue)(ctx);
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

  describe('with user property option issuing an access token', function() {
    var ctx, err;

    before(async function(done) {

      ctx = new Context();
      ctx.state.client = { id: 'c123', name: 'Example' };
      ctx.request.body = { refresh_token: 'refreshing' };

      try {
        await refreshToken({ userProperty: 'client' }, issue)(ctx);
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
