var Server = require('../lib/server');


describe('Server', function() {

  describe('with no exchanges', function() {
    var server = new Server();

    describe('handling a request', function() {
      var err;

      before(async function(done) {
        var ctx = {};

        try {
          await server._exchange(undefined, ctx);
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

  describe('with one exchange registered using a named function', function() {
    var server = new Server();
    server.exchange(code);
    function code(ctx) {
      if (ctx.code != '123') { throw new Error('something is wrong'); }
      ctx.body = 'abc';
    }

    describe('handling a request with supported type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { code: '123' };

        try {
          await server._exchange('code', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should set the body', function() {
        expect(ctx.body).to.equal('abc');
      });
    });

    describe('handling a request with unsupported type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = {};

        try {
          await server._exchange('unsupported', ctx)
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should not set the body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });

    describe('handling a request with undefined type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = {};

        try {
          await server._exchange(undefined, ctx);
        } catch (err) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should not set the body', function() {
        expect(ctx.body).to.be.undefined;
      });
    });
  });

  describe('with a wildcard exchange registered with null', function() {
    var server = new Server();
    server.exchange(null, function(ctx) {
      if (ctx.code != '123') { throw new Error('something is wrong'); }
      ctx.body = 'abc';
    });

    describe('handling a request with type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { code: '123' };

        try {
          await server._exchange('code', ctx);
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

    describe('handling a request without type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { code: '123' };

        try {
          await server._exchange(undefined, ctx);
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

  describe('with a wildcard exchange registered with star', function() {
    var server = new Server();
    server.exchange('*', function(ctx) {
      if (ctx.code != '123') { throw new Error('something is wrong'); }
      ctx.body = 'abc';
    });

    describe('handling a request with type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { code: '123' };

        try {
          await server._exchange('code', ctx);
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

    describe('handling a request without type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { code: '123' };

        try {
          await server._exchange(undefined, ctx);
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

  describe('with multiple exchanges', function() {
    var server = new Server();
    server.exchange('*', function(ctx, next) {
      if (ctx.code != '123') { throw new Error('something is wrong'); }
      ctx.star = true;
      return next();
    });

    server.exchange('code', function(ctx) {
      if (!ctx.star) { throw new Error('something is wrong'); }
      ctx.body = 'abc';
    });

    describe('handling a request with type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { code: '123' };

        try {
          await server._exchange('code', ctx);
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

  describe('with one exchange that encounters an error', function() {
    var server = new Server();
    server.exchange('code', function() {
      throw new Error('something went wrong');
    });

    describe('handling a request with type', function() {
      var ctx, err;

      before(async function(done) {
        ctx = { code: '123' };

        try {
          await server._exchange('code', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong')
      });
    });
  });
});
