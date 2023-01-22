# http-firewall

Lightweight Http Firewall to protect against common threats.

This is a direct port of the [Spring Security HttpFirewall](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html).

- This library is a middleware for Express Server. 
- Its highly recommended not to disable firewall rules, since its extremely risky to do so. You can however provided your own overrides that gives you the options of disable rules or provide your own constraints.
- If a threat is detected, a HTTP status code 403 is returned to the caller, and no further processing happens.
- Calls which pass the firewall rules, will process as normal.

## Examples ##

The firewall can be configured as shown below:

```typescript
import express, { Request, Response } from 'express';
import { HttpFirewallOptions, Predicate } from "../types";
import { StrictHttpFirewall } from "../index";

const app = express();
const port = 3000;

// This must be added first, before adding any routes
app.use(new StrictHttpFirewall(firewallOptions()).firewall)

// Or, to simply use the firewall with default rules:
//app.use(httpFirewall)

app.get('/', (req: Request, res: Response) => {
    res.send('Http Firewall Demo running');
});

app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});


function firewallOptions(): HttpFirewallOptions {
    // Allows traffic from specific hosts only
    const allowedHostnamesPredicate =
        Predicate.of<string>(h => h.endsWith('example.com')).or(
            Predicate.of<string>(h => h === "localhost"));

    return {
        allowedHostnames: allowedHostnamesPredicate,
        allowedHttpMethods: ['POST', 'GET'],
    };
}

```
