import express, {Express, Request, Response} from 'express';
import {HttpFirewallOptions, Predicate} from "../types";
import {StrictHttpFirewall} from "../index";

const app: Express = express();
const port = 5428;

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
