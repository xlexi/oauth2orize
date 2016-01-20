var Server = require('../lib/server');


describe('Server', function() {

  describe('#serializeClient', function() {

    describe('no serializers', function() {
      var server = new Server();

      describe('serializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.serializeClient({ id: '1', name: 'Foo' });
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal('Failed to serialize client. Register serialization function using serializeClient().')
        });
      });
    });

    describe('one serializer', function() {
      var server = new Server();
      server.serializeClient(async function(client) {
        return client.id;
      });

      describe('serializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.serializeClient({ id: '1', name: 'Foo' });
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should not error', function() {
          expect(err).to.be.undefined;
        });

        it('should serialize', function() {
          expect(obj).to.equal('1');
        });
      });
    });

    describe('multiple serializers', function() {
      var server = new Server();
      server.serializeClient(function(client) {
      });
      server.serializeClient(function(client) {
        return '#2';
      });
      server.serializeClient(function(client) {
        return '#3';
      });

      describe('serializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.serializeClient({ id: '1', name: 'Foo' });
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should not error', function() {
          expect(err).to.be.undefined;
        });

        it('should serialize', function() {
          expect(obj).to.equal('#2');
        });
      });
    });

    describe('serializer that encounters an error', function() {
      var server = new Server();
      server.serializeClient(async function() {
        throw new Error('something went wrong');
      });

      describe('serializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.serializeClient({ id: '1', name: 'Foo' });
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

    describe('serializer that throws an exception', function() {
      var server = new Server();
      server.serializeClient(function(client, done) {
        throw new Error('something was thrown')
      });

      describe('serializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.serializeClient({ id: '1', name: 'Foo' });
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

  }); // #serializeClient

  describe('#deserializeClient', function() {

    describe('no deserializers', function() {
      var server = new Server();

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal('Failed to deserialize client. Register deserialization function using deserializeClient().')
        });
      });
    });

    describe('one deserializer', function() {
      var server = new Server();
      server.deserializeClient(async function(id) {
        return { id: id };
      });

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should not error', function() {
          expect(err).to.be.undefined;
        });

        it('should deserialize', function() {
          expect(obj.id).to.equal('1');
        });
      });
    });

    describe('multiple deserializers', function() {
      var server = new Server();
      server.deserializeClient(function(id) {
      });
      server.deserializeClient(function(id) {
        return { id: '#2' };
      });
      server.deserializeClient(function(id) {
        return { id: '#3' };
      });

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should not error', function() {
          expect(err).to.be.undefined;
        });

        it('should deserialize', function() {
          expect(obj.id).to.equal('#2');
        });
      });
    });

    describe('one deserializer to null', function() {
      var server = new Server();
      server.deserializeClient(function(id) {
        return null;
      });

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should not error', function() {
          expect(err).to.be.undefined;
        });

        it('should invalidate client', function() {
          expect(obj).to.be.false;
        });
      });
    });

    describe('one deserializer to false', function() {
      var server = new Server();
      server.deserializeClient(function(id) {
        return false;
      });

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should not error', function() {
          expect(err).to.be.undefined;
        });

        it('should invalidate client', function() {
          expect(obj).to.be.false;
        });
      });
    });

    describe('multiple deserializers to null', function() {
      var server = new Server();
      server.deserializeClient(function() {
      });
      server.deserializeClient(function(id) {
        return null;
      });
      server.deserializeClient(function(id) {
        return { id: '#3' };
      });

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should not error', function() {
          expect(err).to.be.unedefined;
        });

        it('should invalidate client', function() {
          expect(obj).to.be.false;
        });
      });
    });

    describe('multiple deserializers to false', function() {
      var server = new Server();
      server.deserializeClient(function() {
      });
      server.deserializeClient(function(id) {
        return false;
      });
      server.deserializeClient(function(id) {
        return { id: '#3' };
      });

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should not error', function() {
          expect(err).to.be.undefined;
        });

        it('should invalidate client', function() {
          expect(obj).to.be.false;
        });
      });
    });

    describe('deserializer that encounters an error', function() {
      var server = new Server();
      server.deserializeClient(async function(obj) {
        throw new Error('something went wrong');
      });

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
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

    describe('deserializer that throws an exception', function() {
      var server = new Server();
      server.deserializeClient(function(obj) {
        throw new Error('something was thrown');
      });

      describe('deserializing', function() {
        var obj, err;

        before(async function(done) {
          try {
            obj = await server.deserializeClient('1');
          } catch (e) {
            err = e;
          }

          done();
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal('something was thrown')
        });
      });
    });

  }); // #deserializeClient

});
