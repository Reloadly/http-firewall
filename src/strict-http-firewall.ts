import { NextFunction, Request, Response } from 'express';
// import { StrictHttpFirewall } from "./strict.http.firewall";

type PredicateType<T> = (x: T) => boolean;

export class Predicate<T> {
  constructor(private condition: PredicateType<T>) {}

  public static of = <T>(condition: PredicateType<T>) => new Predicate(condition);

  private static isInstance = <T>(input: Predicate<T> | PredicateType<T>): Predicate<T> =>
    input instanceof Predicate ? input : Predicate.of(input);

  public and = (input: Predicate<T> | PredicateType<T>): Predicate<T> =>
    Predicate.of((x: T) => this.test(x) && Predicate.isInstance(input).test(x));

  public or = (input: Predicate<T> | PredicateType<T>): Predicate<T> =>
    Predicate.of((x: T) => this.test(x) || Predicate.isInstance(input).test(x));

  public not = (): Predicate<T> => Predicate.of((x: T) => !this.test(x));

  public test = (x: T): boolean => this.condition(x);
}

export declare type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'TRACE';

/** Firewall initialization options */
export interface HttpFirewallOptions {
  /**
   * Sets if any HTTP method is allowed. If this set to true, then no validation on the
   * HTTP method will be performed. This can open the application up to
   * <a href="https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)"> HTTP
   * Verb tampering and XST attacks</a>
   */
  unsafeAllowAnyHttpMethod?: boolean;

  /**
   * <p>
   * Determines which HTTP methods should be allowed. The default is to allow "DELETE",
   * "GET", "HEAD", "OPTIONS", "PATCH", "POST", and "PUT".
   * </p>
   */
  allowedHttpMethods?: HttpMethod[];

  /**
   * <p>
   * Determines if semicolon is allowed in the URL (i.e. matrix variables). The default
   * is to disable this behavior because it is a common way of attempting to perform
   * <a href="https://www.owasp.org/index.php/Reflected_File_Download">Reflected File
   * Download Attacks</a>. It is also the source of many exploits which bypass URL based
   * security.
   * </p>
   * <p>
   * For example, the following CVEs are a subset of the issues related to ambiguities
   * in the Servlet Specification on how to treat semicolons that led to CVEs:
   * </p>
   * <ul>
   * <li><a href="https://pivotal.io/security/cve-2016-5007">cve-2016-5007</a></li>
   * <li><a href="https://pivotal.io/security/cve-2016-9879">cve-2016-9879</a></li>
   * <li><a href="https://pivotal.io/security/cve-2018-1199">cve-2018-1199</a></li>
   * </ul>
   *
   * <p>
   * If you are wanting to allow semicolons, please reconsider as it is a very common
   * source of security bypasses. A few common reasons users want semicolons and
   * alternatives are listed below:
   * </p>
   * <ul>
   * <li>Including the JSESSIONID in the path - You should not include session id (or
   * any sensitive information) in a URL as it can lead to leaking. Instead use Cookies.
   * </li>
   * <li>Matrix Variables - Users wanting to leverage Matrix Variables should consider
   * using HTTP parameters instead.</li>
   * </ul>
   *
   * Default is false
   */
  allowSemicolon?: boolean;

  /**
   * <p>
   * Determines if a slash "/" that is URL encoded "%2F" should be allowed in the path
   * or not. The default is to not allow this behavior because it is a common way to
   * bypass URL based security.
   * </p>
   * <p>
   * For example, due to ambiguities in the servlet specification, the value is not
   * parsed consistently which results in different values in {@code HttpServletRequest}
   * path related values which allow bypassing certain security constraints.
   * </p>
   *
   * Default is false.
   */
  allowUrlEncodedSlash?: boolean;

  /**
   * <p>
   * Determines if double slash "//" that is URL encoded "%2F%2F" should be allowed in
   * the path or not. The default is to not allow.
   * </p>
   * Default is false.
   */
  allowUrlEncodedDoubleSlash?: boolean;

  /**
   * <p>
   * Determines if a period "." that is URL encoded "%2E" should be allowed in the path
   * or not. The default is to not allow this behavior because it is a frequent source
   * of security exploits.
   * </p>
   * <p>
   * For example, due to ambiguities in the servlet specification a URL encoded period
   * might lead to bypassing security constraints through a directory traversal attack.
   * This is because the path is not parsed consistently which results in different
   * values in {@code HttpServletRequest} path related values which allow bypassing
   * certain security constraints.
   * </p>
   * Default is false.
   */
  allowUrlEncodedPeriod?: boolean;

  /**
   * <p>
   * Determines if a backslash "\" or a URL encoded backslash "%5C" should be allowed in
   * the path or not. The default is not to allow this behavior because it is a frequent
   * source of security exploits.
   * </p>
   * <p>
   * For example, due to ambiguities in the servlet specification a URL encoded period
   * might lead to bypassing security constraints through a directory traversal attack.
   * This is because the path is not parsed consistently which results in different
   * values in {@code HttpServletRequest} path related values which allow bypassing
   * certain security constraints.
   * </p>
   * Default is false
   */
  allowBackSlash?: boolean;

  /**
   * <p>
   * Determines if a null "\0" or a URL encoded nul "%00" should be allowed in the path
   * or not. The default is not to allow this behavior because it is a frequent source
   * of security exploits.
   * </p>
   * Default is false
   */
  allowNull?: boolean;

  /**
   * <p>
   * Determines if a percent "%" that is URL encoded "%25" should be allowed in the path
   * or not. The default is not to allow this behavior because it is a frequent source
   * of security exploits.
   * </p>
   * <p>
   * For example, this can lead to exploits that involve double URL encoding that lead
   * to bypassing security constraints.
   * </p>
   * Default is false
   */
  allowUrlEncodedPercent?: boolean;

  /**
   * Determines if a URL encoded Carriage Return is allowed in the path or not. The
   * default is not to allow this behavior because it is a frequent source of security
   * exploits.
   * Default is false.
   */
  allowUrlEncodedCarriageReturn?: boolean;

  /**
   * Determines if a URL encoded Line Feed is allowed in the path or not. The default is
   * not to allow this behavior because it is a frequent source of security exploits.
   * Default is false.
   */
  allowUrlEncodedLineFeed?: boolean;

  /**
   * Determines if a URL encoded paragraph separator is allowed in the path or not. The
   * default is not to allow this behavior because it is a frequent source of security
   * exploits.
   * Default is false.
   */
  allowUrlEncodedParagraphSeparator?: boolean;

  /**
   * Determines if a URL encoded line separator is allowed in the path or not. The
   * default is not to allow this behavior because it is a frequent source of security
   * exploits.
   * Default is false.
   */
  allowUrlEncodedLineSeparator?: boolean;

  /**
   * <p>
   * Determines which header names should be allowed. The default is to reject header
   * names that contain ISO control characters and characters that are not defined.
   * </p>
   */
  allowedHeaderNames?: Predicate<string>;

  /**
   * <p>
   * Determines which header values should be allowed. The default is to reject header
   * values that contain ISO control characters and characters that are not defined.
   * </p>
   */
  allowedHeaderValues?: Predicate<string>;

  /**
   * Determines which parameter names should be allowed. The default is to reject header
   * names that contain ISO control characters and characters that are not defined.
   * @param allowedParameterNames the predicate for testing parameter names
   */
  allowedParameterNames?: Predicate<string>;

  /**
   * <p>
   * Determines which parameter values should be allowed. The default is to allow any
   * parameter value.
   * </p>
   */
  allowedParameterValues?: Predicate<string>;

  /**
   * <p>
   * Determines which hostnames should be allowed. The default is to allow any hostname.
   * </p>
   */
  allowedHostnames?: Predicate<string>;

  /**
   * Whether to log rejections to console.
   * Default is false
   */
  logToConsole?: boolean;
}

class RequestRejectedError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = 'RequestRejectedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export const httpFirewall = (options?: HttpFirewallOptions) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    return await new StrictHttpFirewall(options).firewall(req, res, next);
  };
};

class StrictHttpFirewall {
  // Pre-defined constraints. These can be overriden
  private readonly ALLOW_ANY_HTTP_METHOD: HttpMethod[] = [];
  private readonly ENCODED_PERCENT: string = '%25';
  private readonly PERCENT: string = '%';
  private readonly FORBIDDEN_ENCODED_PERIOD: string[] = ['%2e', '%2E'];
  private readonly FORBIDDEN_SEMICOLON: string[] = [';', '%3b', '%3B'];
  private readonly FORBIDDEN_FORWARDSLASH: string[] = ['%2f', '%2F'];
  private readonly FORBIDDEN_DOUBLE_FORWARDSLASH: string[] = ['//', '%2f%2f', '%2f%2F', '%2F%2f', '%2F%2F'];
  private readonly FORBIDDEN_BACKSLASH: string[] = ['\\', '%5c', '%5C'];
  private readonly FORBIDDEN_NULL: string[] = ['\0', '%00'];
  private readonly FORBIDDEN_LF: string[] = ['\n', '%0a', '%0A'];
  private readonly FORBIDDEN_CR: string[] = ['\r', '%0d', '%0D'];
  private readonly FORBIDDEN_LINE_SEPARATOR: string[] = ['\u2028'];
  private readonly FORBIDDEN_PARAGRAPH_SEPARATOR: string[] = ['\u2029'];

  private logToConsole: boolean = false;
  private encodedUrlBlocklist: string[] = [];
  private decodedUrlBlocklist: string[] = [];
  private readonly allowedHttpMethods: HttpMethod[] = this.createDefaultAllowedHttpMethods();
  private readonly allowedHostnames: Predicate<String> = new Predicate<string>((hostName) => true);
  private readonly ASSIGNED_AND_NOT_ISO_CONTROL_PATTERN: RegExp = new RegExp(
    `[\p{IsAssigned}&&[^\p{IsControl}]]*`,
    'g',
  );
  private readonly ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE: Predicate<string> = new Predicate<string>((testName) =>
    this.ASSIGNED_AND_NOT_ISO_CONTROL_PATTERN.test(testName),
  );
  private allowedHeaderNames: Predicate<String> = this.ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE;
  private allowedHeaderValues: Predicate<String> = this.ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE;
  private allowedParameterNames: Predicate<String> = this.ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE;
  private allowedParameterValues: Predicate<String> = new Predicate<string>((value) => true);

  public constructor(options?: HttpFirewallOptions) {
    this.urlBlocklistsAddAll(this.FORBIDDEN_SEMICOLON);
    this.urlBlocklistsAddAll(this.FORBIDDEN_FORWARDSLASH);
    this.urlBlocklistsAddAll(this.FORBIDDEN_DOUBLE_FORWARDSLASH);
    this.urlBlocklistsAddAll(this.FORBIDDEN_BACKSLASH);
    this.urlBlocklistsAddAll(this.FORBIDDEN_NULL);
    this.urlBlocklistsAddAll(this.FORBIDDEN_LF);
    this.urlBlocklistsAddAll(this.FORBIDDEN_CR);
    this.encodedUrlBlocklist.push(this.ENCODED_PERCENT);
    this.encodedUrlBlocklist.push(...this.FORBIDDEN_ENCODED_PERIOD);
    this.decodedUrlBlocklist.push(this.PERCENT);
    this.encodedUrlBlocklist.push(...this.FORBIDDEN_LINE_SEPARATOR);
    this.encodedUrlBlocklist.push(...this.FORBIDDEN_PARAGRAPH_SEPARATOR);

    if (options !== undefined) {
      if (options.logToConsole === true) {
        this.logToConsole = true;
      }

      this.allowedHttpMethods =
        options.unsafeAllowAnyHttpMethod === true ? this.ALLOW_ANY_HTTP_METHOD : this.createDefaultAllowedHttpMethods();

      if (options.allowedHttpMethods !== undefined) {
        this.allowedHttpMethods =
          options.allowedHttpMethods.length !== 0 ? options.allowedHttpMethods : this.ALLOW_ANY_HTTP_METHOD;
      }

      if (options.allowSemicolon === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_SEMICOLON);
      } else {
        this.urlBlocklistsAddAll(this.FORBIDDEN_SEMICOLON);
      }

      if (options.allowUrlEncodedSlash === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_FORWARDSLASH);
      } else {
        this.urlBlocklistsAddAll(this.FORBIDDEN_FORWARDSLASH);
      }

      if (options.allowUrlEncodedDoubleSlash === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_DOUBLE_FORWARDSLASH);
      } else {
        this.urlBlocklistsAddAll(this.FORBIDDEN_DOUBLE_FORWARDSLASH);
      }

      if (options.allowUrlEncodedPeriod === true) {
        this.removeItems(this.encodedUrlBlocklist, this.FORBIDDEN_ENCODED_PERIOD);
      } else {
        this.encodedUrlBlocklist.push(...this.FORBIDDEN_ENCODED_PERIOD);
      }

      if (options.allowBackSlash === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_BACKSLASH);
      } else {
        this.urlBlocklistsAddAll(this.FORBIDDEN_BACKSLASH);
      }

      if (options.allowNull === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_NULL);
      } else {
        this.urlBlocklistsAddAll(this.FORBIDDEN_NULL);
      }

      if (options.allowUrlEncodedPercent === true) {
        this.removeItems(this.encodedUrlBlocklist, [this.ENCODED_PERCENT]);
        this.removeItems(this.decodedUrlBlocklist, [this.PERCENT]);
      } else {
        this.encodedUrlBlocklist.push(this.ENCODED_PERCENT);
        this.decodedUrlBlocklist.push(this.PERCENT);
      }

      if (options.allowUrlEncodedCarriageReturn === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_CR);
      } else {
        this.urlBlocklistsAddAll(this.FORBIDDEN_CR);
      }

      if (options.allowUrlEncodedLineFeed === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_LF);
      } else {
        this.urlBlocklistsAddAll(this.FORBIDDEN_LF);
      }

      if (options.allowUrlEncodedParagraphSeparator === true) {
        this.removeItems(this.encodedUrlBlocklist, this.FORBIDDEN_PARAGRAPH_SEPARATOR);
      } else {
        this.encodedUrlBlocklist.push(...this.FORBIDDEN_PARAGRAPH_SEPARATOR);
      }

      if (options.allowUrlEncodedLineSeparator === true) {
        this.removeItems(this.encodedUrlBlocklist, this.FORBIDDEN_LINE_SEPARATOR);
      } else {
        this.encodedUrlBlocklist.push(...this.FORBIDDEN_LINE_SEPARATOR);
      }

      if (options.allowedHeaderNames !== undefined) {
        this.allowedHeaderNames = options.allowedHeaderNames;
      }

      if (options.allowedHeaderValues !== undefined) {
        this.allowedHeaderValues = options.allowedHeaderValues;
      }

      if (options.allowedParameterNames !== undefined) {
        this.allowedParameterNames = options.allowedParameterNames;
      }

      if (options.allowedParameterValues !== undefined) {
        this.allowedParameterValues = options.allowedParameterValues;
      }

      if (options.allowedHostnames !== undefined) {
        this.allowedHostnames = options.allowedHostnames;
      }
    }
  }

  private static isNormalizedRequest = (req: Request): boolean => {
    if (!StrictHttpFirewall.isNormalized(req.url)) {
      return false;
    }
    if (!StrictHttpFirewall.isNormalized(req.originalUrl)) {
      return false;
    }
    if (!StrictHttpFirewall.isNormalized(req.path)) {
      return false;
    }
    return StrictHttpFirewall.isNormalized(req.route);
  };

  private static encodedUrlContains = (req: Request, value: string): boolean => {
    if (StrictHttpFirewall.valueContains(req.path, value)) {
      return true;
    }

    return StrictHttpFirewall.valueContains(req.url, value);
  };

  private static decodedUrlContains = (req: Request, value: string): boolean => {
    return StrictHttpFirewall.valueContains(req.path, value);
  };

  private static containsOnlyPrintableAsciiCharacters = (uri: string): boolean => {
    if (uri === undefined || uri === null) {
      return true;
    }
    const length = uri.length;

    for (let i = 0; i < length; i++) {
      const ch = uri.charAt(i);
      if (ch < '\u0020' || ch > '\u007e') {
        return false;
      }
    }
    return true;
  };

  private static valueContains = (value: string, contains: string): boolean => {
    return value != null && value.indexOf(contains) !== -1;
  };

  /**
   * Checks whether a path is normalized (doesn't contain path traversal sequences like
   * "./", "/../" or "/.")
   * @param path the path to test
   * @return true if the path doesn't contain any path-traversal character sequences.
   */
  private static isNormalized = (path: string): boolean => {
    if (path === undefined || path === null) {
      return true;
    }

    for (let i = path.length; i > 0; ) {
      let slashIndex = path.lastIndexOf('/', i - 1);
      let gap = i - slashIndex;
      if (gap == 2 && path.charAt(slashIndex + 1) == '.') {
        return false; // ".", "/./" or "/."
      }
      if (gap == 3 && path.charAt(slashIndex + 1) == '.' && path.charAt(slashIndex + 2) == '.') {
        return false;
      }
      i = slashIndex;
    }
    return true;
  };

  public firewall = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    await this.rejectForbiddenHttpMethod(req)
      .then(() => this.rejectedBlocklistedUrls(req))
      .then(() => this.rejectedUntrustedHosts(req))
      .then(() => this.rejectNonNormalizedRequests(req))
      .then(() => this.rejectNonPrintableAsciiCharactersInFieldName(req, req.url, 'requestURI'))
      .then(() => next())
      .catch((error) => {
        if (this.logToConsole === true) {
          console.warn(error.message);
        }
        this.reject(req, res);
      });
  };

  private rejectNonNormalizedRequests = async (req: Request): Promise<void> => {
    if (!StrictHttpFirewall.isNormalizedRequest(req)) {
      throw new RequestRejectedError(`The request was rejected because the URL was not normalized.`);
    }
  };

  private rejectNonPrintableAsciiCharactersInFieldName = async (
    req: Request,
    toCheck: string,
    propertyName: string,
  ): Promise<void> => {
    if (!StrictHttpFirewall.containsOnlyPrintableAsciiCharacters(toCheck)) {
      throw new RequestRejectedError(
        `The ${propertyName} was rejected because it can only contain ` + `printable ASCII characters.`,
      );
    }
  };

  private urlBlocklistsAddAll(values: string[]) {
    this.encodedUrlBlocklist.push(...values);
    this.decodedUrlBlocklist.push(...values);
  }

  private urlBlocklistsRemoveAll(values: string[]) {
    this.removeItems(this.encodedUrlBlocklist, values);
    this.removeItems(this.decodedUrlBlocklist, values);
  }

  private removeItems(originalArray: string[], itemsTobeRemoved: string[]) {
    for (const item of itemsTobeRemoved) {
      const index = originalArray.indexOf(item);
      if (index !== -1) {
        originalArray.splice(index, 1);
      }
    }
  }

  private rejectedBlocklistedUrls = async (req: Request): Promise<void> => {
    const errorMessage =
      `The request was rejected because the URL contained a potentially ` + `malicious String ${req.url}`;
    const error = new RequestRejectedError(errorMessage);

    for (const forbidden of this.encodedUrlBlocklist) {
      if (StrictHttpFirewall.encodedUrlContains(req, forbidden)) {
        throw error;
      }
    }

    for (const forbidden of this.decodedUrlBlocklist) {
      if (StrictHttpFirewall.decodedUrlContains(req, forbidden)) {
        throw error;
      }
    }
  };

  private rejectedUntrustedHosts = async (req: Request): Promise<void> => {
    const serverName = req.hostname;
    if (serverName !== undefined && serverName !== null && !this.allowedHostnames.test(serverName)) {
      throw new RequestRejectedError(`The request was rejected because the domain ${serverName} is untrusted.`);
    }
  };

  private rejectForbiddenHttpMethod = async (req: Request): Promise<void> => {
    if (this.allowedHttpMethods === this.ALLOW_ANY_HTTP_METHOD) {
      return;
    }

    const method = <HttpMethod>req.method.toUpperCase();
    if (this.allowedHttpMethods.indexOf(method) === -1) {
      throw new RequestRejectedError(
        `The request was rejected because the HTTP method ${method} was not ` +
          `included within the list of allowed HTTP methods + ${this.allowedHttpMethods}`,
      );
    }
  };

  private reject = (req: Request, res: Response) => {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('FORBIDDEN');
  };

  private createDefaultAllowedHttpMethods(): HttpMethod[] {
    return ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT'];
  }
}

