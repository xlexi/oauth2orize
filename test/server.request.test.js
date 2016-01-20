var Server = require('../lib/server');


describe('Server', function() {

  describe('parsing authorization requests with one supported type', function() {
    var server = new Server();
    server.grant('foo', function(ctx) {
      return { foo: ctx.query.foo }
    });

    describe('request for supported type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = { query: { foo: '1' } };

        try {
          var ar = await server._parse('foo', ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(areq).to.be.an('object');
        expect(Object.keys(areq)).to.have.length(2);
        expect(areq.type).to.equal('foo');
        expect(areq.foo).to.equal('1');
      });
    });

    describe('request for unsupported type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = { query: { foo: '1' } };

        try {
          var ar = await server._parse('bar', ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse only type', function() {
        expect(areq).to.be.an('object');
        expect(Object.keys(areq)).to.have.length(1);
        expect(areq.type).to.equal('bar');
      });
    });

    describe('request for undefined type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = { query: { foo: '1' } };

        try {
          var ar = await server._parse(undefined, ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should not parse request', function() {
        expect(areq).to.be.an('object');
        expect(Object.keys(areq)).to.have.length(0);
      });
    });
  });

  describe('parsing authorization requests with one wildcard parser', function() {
    var server = new Server();
    server.grant('*', function(ctx) {
      return { star: ctx.query.star }
    });

    describe('request for type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = { query: { star: 'orion' } };

        try {
          var ar = await server._parse('foo', ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(areq).to.be.an('object');
        expect(Object.keys(areq)).to.have.length(2);
        expect(areq.type).to.equal('foo');
        expect(areq.star).to.equal('orion');
      });
    });
  });

  describe('parsing authorization requests with a wildcard parser and one supported type', function() {
    var server = new Server();
    server.grant('*', function(ctx) {
      return { star: ctx.query.star }
    });
    server.grant('bar', function(ctx) {
      return { bar: ctx.query.bar }
    });

    describe('request for supported type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = { query: { bar: '10', star: 'orion' } };

        try {
          var ar = await server._parse('bar', ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(areq).to.be.an('object');
        expect(Object.keys(areq)).to.have.length(3);
        expect(areq.type).to.equal('bar');
        expect(areq.star).to.equal('orion');
        expect(areq.bar).to.equal('10');
      });
    });
  });

  describe('parsing authorization requests with no supported types', function() {
    var server = new Server();

    describe('request for type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = {};

        try {
          var ar = await server._parse('foo', ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse only type', function() {
        expect(areq).to.be.an('object');
        expect(Object.keys(areq)).to.have.length(1);
        expect(areq.type).to.equal('foo');
      });
    });

    describe('request for undefined type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = {};

        try {
          var ar = await server._parse(undefined, ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should not parse request', function() {
        expect(areq).to.be.an('object');
        expect(Object.keys(areq)).to.have.length(0);
      });
    });
  });

  describe('parsing authorization requests with an async wildcard parser preceeding one supported type', function() {
    var server = new Server();
    server.grant('*', async function(req) {
      return { star: req.query.star };
    });
    server.grant('bar', function(req) {
      return { bar: req.query.bar }
    })

    describe('request for supported type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = { query: { bar: '10', star: 'orion' } };

        try {
          var ar = await server._parse('bar', ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(areq).to.be.an('object');
        expect(Object.keys(areq)).to.have.length(3);
        expect(areq.type).to.equal('bar');
        expect(areq.star).to.equal('orion');
        expect(areq.bar).to.equal('10');
      });
    });
  });

  describe('parsing requests with an async wildcard parser that encounters an error preceeding one supported type', function() {
    var server = new Server();
    server.grant('*', function(req) {
      throw new Error('something went wrong');
    });
    server.grant('bar', function(req) {
      return { bar: req.query.bar }
    })

    describe('request for supported type', function() {
      var areq, err;

      before(async function(done) {
        var ctx = { query: { bar: '10', star: 'orion' } };

        try {
          var ar = await server._parse('bar', ctx);
          areq = ar;
        } catch (e) {
          err = e;
        }
        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });

      it('should not parse object', function() {
        expect(areq).to.be.undefined;
      });
    });
  });

});
