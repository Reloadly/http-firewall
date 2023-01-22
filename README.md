# http-firewall

Lightweight Http Firewall to protect against common threats.

This is a direct port of
the [Spring Security HttpFirewall](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html).

- This library is a middleware for Express Server.
- Its highly recommended not to disable firewall rules, since its extremely risky to do so. You can however provided
  your own overrides that gives you the options of disable rules or provide your own constraints.
- If a threat is detected, a HTTP status code 403 is returned to the caller, and no further processing happens.
- Calls which pass the firewall rules, will process as normal.

## Examples ##

The firewall can be configured as shown below:

### TypeScript Usage ###

```typescript
import express, { Request, Response } from 'express';
import { HttpFirewallOptions, Predicate, httpFirewall } from '@prizemates/http-firewall';

const app = express();
const port = 3000;

// This middleware must be added before adding any other routes
app.use(httpFirewall())
// Or, you can customize the behaviour by providing options. See HttpFirewallOptions
// app.use(httpFirewall({logToConsole : true}));

app.get('/', (req: Request, res: Response) => {
  res.send('Http Firewall Demo running');
});

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});
```

### Javascript Usage ###

```javascript
const express = require("express");
const { httpFirewall } = require("@prizemates/http-firewall");

const app = express();
const port = 3000;

app.use(httpFirewall())
// Or, you can customize the behaviour by providing options. See HttpFirewallOptions
// app.use(httpFirewall({logToConsole : true}));

app.get('/', (req: Request, res: Response) => {
  res.send('Http Firewall Demo running');
});

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});
```
