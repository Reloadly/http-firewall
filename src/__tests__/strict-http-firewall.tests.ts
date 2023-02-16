import { httpFirewall } from '../strict-http-firewall';
import { HttpFirewallOptions, HttpMethod } from '../types';
import express from 'express';
import request from 'supertest';

describe('HttpStrictFirewall test suite', () => {
  const unNormalizedPathsThatCanBeHandledBySupertest: string[] = [
    '/..',
    '/./path/',
    '/path/path/.',
    '/path/path//.',

    '//path',
    '//path/path',
    '//path//path',
    '/path//path',
  ];

  // const unNormalizedPathsTrappedBySanitizer: string[] = [
  //   "./path/../path//.",
  //   "./path",
  //   ".//path",
  //   ".",
  //   "/..",
  //   "/./path/",
  //   "/path/path/.",
  //   "/path/path//."
  // ];
  // describe('URL Normalization Tests: .isNormalized()', () => {
  //
  //   for (const path of unNormalizedPathsTrappedBySanitizer) {
  //     test(`Should reject un-normalized path: ${path}`, async () => {
  //       const fw = new StrictHttpFirewall();
  //       // const fwProto = Object.getPrototypeOf(fw);
  //
  //       const valid = fw.isNormalized(path);
  //       expect(valid).toBe(false)
  //     });
  //   }
  // });

  describe('Integration Tests: .firewall()', () => {
    it('Should block XST attacks using TRACE', async () => {
      const app = express();
      app.use(httpFirewall());
      const res = await request(app).trace('/').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('When valid methods are used, call should not be rejected', async () => {
      const app = express();
      app.use(httpFirewall());
      setupRoutes(app, ['GET', 'PUT', 'POST', 'HEAD', 'OPTIONS', 'DELETE', 'PATCH']);

      let res = await request(app).get('/');
      expect(res.statusCode).toBe(200);

      res = await request(app).put('/');
      expect(res.statusCode).toBe(200);

      res = await request(app).post('/');
      expect(res.statusCode).toBe(200);

      res = await request(app).head('/');
      expect(res.statusCode).toBe(200);

      res = await request(app).options('/');
      expect(res.statusCode).toBe(200);

      res = await request(app).delete('/');
      expect(res.statusCode).toBe(200);

      res = await request(app).patch('/');
      expect(res.statusCode).toBe(200);
    });

    it('When any methods are allowed unsafely, call should not be rejected', async () => {
      const app = express();
      app.use(httpFirewall({ unsafeAllowAnyHttpMethod: true }));
      setupRoutes(app, ['TRACE']);

      let res = await request(app).trace('/');
      expect(res.statusCode).toBe(200);
    });

    describe('Un-Normalized URI paths should be rejected', () => {
      for (const path of unNormalizedPathsThatCanBeHandledBySupertest) {
        it(`Should reject un-normalized path: ${path}`, async () => {
          // console.log(`Path = ${path}`)
          let app = express();
          app.use(httpFirewall());
          setupRoutes(app, ['GET']);
          let res = await request(app).get(path);
          expect(res.statusCode).toBe(403);
        });
      }
    });

    it('Should reject disallowed Http method', async () => {
      const app = express();

      const options: HttpFirewallOptions = {
        allowedHttpMethods: ['POST', 'GET'],
      };
      app.use(httpFirewall(options));
      const res = await request(app).head('/').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('Should reject path with semicolon', async () => {
      const app = express();

      const options: HttpFirewallOptions = {
        allowedHttpMethods: ['POST', 'GET'],
      };
      app.use(httpFirewall(options));
      const res = await request(app).get('/context;').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('Should not reject path with semicolon when its allowed', async () => {
      const app = express();

      const options: HttpFirewallOptions = {
        allowSemicolon: true,
      };
      app.use(httpFirewall(options));
      const res = await request(app).get('/;').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(404);
    });

    it('Should reject encoded percent', async () => {
      const app = express();

      const options: HttpFirewallOptions = {};
      app.use(httpFirewall(options));
      const res = await request(app).get('/%25').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('Should reject encoded period', async () => {
      const app = express();

      const options: HttpFirewallOptions = {};
      app.use(httpFirewall(options));
      const res = await request(app).get('/%2e').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('Should reject request when user provided decoded url block list is provided', async () => {
      const app = express();

      const options: HttpFirewallOptions = {decodedUrlBlockList : ['.exe', '.pl']};
      app.use(httpFirewall(options));
      const res = await request(app).get('/test/some-file.exe').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('Should reject request when user provided encoded url block list is provided', async () => {
      const app = express();

      const options: HttpFirewallOptions = {encodedUrlBlockList : ['.exe', '.pl']};
      app.use(httpFirewall(options));
      const res = await request(app).get('/test/some-file.exe').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('Should allow encoded period when permitted', async () => {
      const app = express();

      const options: HttpFirewallOptions = {
        allowUrlEncodedPeriod: true,
        allowUrlEncodedPercent: true,
      };
      app.use(httpFirewall(options));
      setupRoutes(app, ['GET']);

      const res = await request(app).get('/%2e').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(404);
    });

    // TODO: THis test is not correct
    it('Should reject when lower bound hit for ascii chars', async () => {
      const app = express();

      const options: HttpFirewallOptions = {};
      app.use(httpFirewall(options));
      setupRoutes(app, ['GET']);

      const res = await request(app).get('/test/\\u0019').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('Should allow Japanese chars', async () => {
      const app = express();

      const options: HttpFirewallOptions = {
        allowBackSlash: true,
        allowUrlEncodedSlash: true,
        allowUrlEncodedDoubleSlash: true,
      };
      app.use(httpFirewall(options));
      setupRoutes(app, ['GET']);

      const res = await request(app).get('/test/\\u3042').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(404);
    });

    it('Should not reject  encoded percent when its permitted', async () => {
      const app = express();

      const options: HttpFirewallOptions = {
        allowUrlEncodedPercent: true,
      };
      app.use(httpFirewall(options));
      const res = await request(app).get('/%25').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(404);
    });

    it('Should reject encoded semicolon', async () => {
      const app = express();

      const options: HttpFirewallOptions = {
        allowedHttpMethods: ['POST', 'GET'],
      };
      app.use(httpFirewall(options));
      const res = await request(app).get('/context%3B').set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    it('Should allow configured Http method', async () => {
      // Arrange
      const app = express();
      const options: HttpFirewallOptions = {
        allowedHttpMethods: ['POST', 'GET'],
      };
      app.use(httpFirewall(options));
      app.get('/', (req, res) => {
        // You're working with an express req and res now.
        res.status(200).send();
      });

      // Act
      const res = await request(app).get('/').set('Content-Type', 'application/json');

      // Assert
      expect(res.statusCode).toBe(200);
    });
  });
});

const setupRoutes = (app, methods: HttpMethod[]) => {
  for (const method of methods) {
    switch (method) {
      case 'GET':
        app.get('/', (req, res) => {
          // You're working with an express req and res now.
          res.status(200).send();
        });
        break;
      case 'POST':
        app.post('/', (req, res) => {
          // You're working with an express req and res now.
          res.status(200).send();
        });
        break;
      case 'DELETE':
        app.delete('/', (req, res) => {
          // You're working with an express req and res now.
          res.status(200).send();
        });
        break;
      case 'HEAD':
        app.head('/', (req, res) => {
          // You're working with an express req and res now.
          res.status(200).send();
        });
        break;
      case 'OPTIONS':
        app.options('/', (req, res) => {
          // You're working with an express req and res now.
          res.status(200).send();
        });
        break;
      case 'PATCH':
        app.patch('/', (req, res) => {
          // You're working with an express req and res now.
          res.status(200).send();
        });
        break;
      case 'PUT':
        app.put('/', (req, res) => {
          // You're working with an express req and res now.
          res.status(200).send();
        });
        break;
      case 'TRACE':
        app.trace('/', (req, res) => {
          // You're working with an express req and res now.
          res.status(200).send();
        });
        break;
    }
  }
};
