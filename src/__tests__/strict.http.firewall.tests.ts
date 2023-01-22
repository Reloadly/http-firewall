import { HttpFirewallOptions } from '../types';
import { StrictHttpFirewall } from '../strict.http.firewall';
import express from 'express';
import request from 'supertest';

describe('HttpStrictFirewall test suite', () => {
  describe('Integration Tests: .firewall()', () => {
    test('Should reject disallowed Http method', async () => {
      const app = express();
      const options: HttpFirewallOptions = {
        allowedHttpMethods: ['POST', 'GET'],
      };
      app.use(new StrictHttpFirewall(options).firewall);
      const res = await request(app)
        .head('/')
        .set('Content-Type', 'application/json');
      expect(res.statusCode).toBe(403);
    });

    test('Should allow configured Http method', async () => {
      // Arrange
      const app = express();
      const options: HttpFirewallOptions = {
        allowedHttpMethods: ['POST', 'GET'],
      };
      app.use(new StrictHttpFirewall(options).firewall);
      app.get('/', (req, res) => {
        // You're working with an express req and res now.
        res.status(200).send();
      });

      // Act
      const res = await request(app)
        .get('/')
        .set('Content-Type', 'application/json');

      // Assert
      expect(res.statusCode).toBe(200);
    });
  });
});
