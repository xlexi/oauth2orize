var Server = require('../lib/server');


describe('Server', function() {

  describe('handling authorization response with one supported type', function() {
    var server = new Server();
    server.grant('foo', 'response', function(ctx) {
      if (ctx.state.oauth2.req.scope != 'read') { throw new Error('something is wrong'); }
      ctx.body = 'abc';
    });

    describe('response to supported type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { state: {oauth2: {req: { type: 'foo', scope: 'read' } } } };

        try {
          await server._respond(ctx);
        } catch (e) {
          err = e;
        }

        done();

      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should send response', function() {
        expect(ctx.body).to.equal('abc');
      });
    });

    describe('response to unsupported type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = ctx = { state: {oauth2: {req: { type: 'unsupported' } } } };

        try {
          await server._respond(ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });
    });
  });

  describe('handling authorization response with one wildcard responder', function() {
    var server = new Server();
    server.grant('*', 'response', function(ctx) {
      ctx.body = 'abc';
    });

    describe('response to a type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { state: {oauth2: {req: { type: 'foo', scope: 'read' } } } };

        try {
          await server._respond(ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should send response', function() {
        expect(ctx.body).to.equal('abc');
      });
    });
  });

  describe('handling authorization response with one wildcard responder and one supported type', function() {
    var server = new Server();
    server.grant('*', 'response', function(ctx, next) {
      ctx.star = true;
      return next();
    });
    server.grant('foo', 'response', function(ctx) {
      if (!ctx.star) { return next(new Error('something is wrong')); }
      ctx.body = 'abc';
    });

    describe('response to a type', function() {
      var response, ctx, err;

      before(async function(done) {
        ctx = { state: {oauth2: {req: { type: 'foo', scope: 'read' } } } };

        try {
          await server._respond(ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should send response', function() {
        expect(ctx.body).to.equal('abc');
      });
    });
  });

  describe('handling authorization response with responder that encounters an error', function() {
    var server = new Server();
    server.grant('foo', 'response', function() {
      throw new Error('something went wrong');
    });

    describe('response to a type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { state: {oauth2: {req: { type: 'foo', scope: 'read' } } } };

        try {
          await server._respond(ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    });
  });

  describe('handling authorization response with responder that throws an exception', function() {
    var server = new Server();
    server.grant('foo', 'response', async function() {
      throw new Error('something was thrown');
    });

    describe('response to a type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { state: {oauth2: {req: { type: 'foo', scope: 'read' } } } };
        try {
          await server._respond(ctx);
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
  });

  describe('handling authorization response with no supported types', function() {
    var server = new Server();

    describe('response', function() {
      var err;

      before(async function(done) {
        var ctx = { state: {oauth2: {req: { type: 'foo', scope: 'read' } } } };

        try {
          await server._respond(ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });
    });
  });

});
