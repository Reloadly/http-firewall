import { NextFunction, Request, Response } from 'express';
import { HttpFirewallOptions, HttpMethod, Predicate } from './types';

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

  private readonly logToConsole: boolean = false;
  private encodedUrlBlocklist: string[] = [];
  private decodedUrlBlocklist: string[] = [];
  private readonly allowedHttpMethods: HttpMethod[] = this.createDefaultAllowedHttpMethods();
  private readonly allowedHostnames: Predicate<String> = new Predicate<string>((hostName) => true);
  private readonly ASSIGNED_AND_NOT_ISO_CONTROL_PATTERN: RegExp = new RegExp(
    '[\\p{IsAssigned}&&[^\\p{IsControl}]]*',
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
      }

      if (options.allowUrlEncodedSlash === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_FORWARDSLASH);
      }

      if (options.allowUrlEncodedDoubleSlash === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_DOUBLE_FORWARDSLASH);
      }

      if (options.allowUrlEncodedPeriod === true) {
        this.removeItems(this.encodedUrlBlocklist, this.FORBIDDEN_ENCODED_PERIOD);
      }

      if (options.allowBackSlash === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_BACKSLASH);
      }

      if (options.allowNull === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_NULL);
      }

      if (options.allowUrlEncodedPercent === true) {
        this.removeItems(this.encodedUrlBlocklist, [this.ENCODED_PERCENT]);
        this.removeItems(this.decodedUrlBlocklist, [this.PERCENT]);
      }

      if (options.allowUrlEncodedCarriageReturn === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_CR);
      }

      if (options.allowUrlEncodedLineFeed === true) {
        this.urlBlocklistsRemoveAll(this.FORBIDDEN_LF);
      }

      if (options.allowUrlEncodedParagraphSeparator === true) {
        this.removeItems(this.encodedUrlBlocklist, this.FORBIDDEN_PARAGRAPH_SEPARATOR);
      }

      if (options.allowUrlEncodedLineSeparator === true) {
        this.removeItems(this.encodedUrlBlocklist, this.FORBIDDEN_LINE_SEPARATOR);
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

      if (options.decodedUrlBlockList !== undefined && options.decodedUrlBlockList.length !== 0) {
        this.decodedUrlBlocklist.push(... options.decodedUrlBlockList);
      }

      if (options.encodedUrlBlockList !== undefined && options.encodedUrlBlockList.length !== 0) {
        this.encodedUrlBlocklist.push(... options.encodedUrlBlockList);
      }
    }
  }

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

  private isNormalizedRequest = (req: Request): boolean => {
    if (!this.isNormalized(req.url)) {
      return false;
    }
    if (!this.isNormalized(req.originalUrl)) {
      return false;
    }
    if (!this.isNormalized(req.path)) {
      return false;
    }
    return this.isNormalized(req.route);
  };

  private static encodedUrlContains = (req: Request, value: string): boolean => {
    if (StrictHttpFirewall.valueContains(req.path, value)) {
      return true;
    }

    if (StrictHttpFirewall.valueContains(req.url, value)) {
      return true;
    }

    if (StrictHttpFirewall.valueContains(req.baseUrl, value)) {
      return true;
    }

    if (StrictHttpFirewall.valueContains(req.originalUrl, value)) {
      return true;
    }

    return StrictHttpFirewall.valueContains(req.route, value);
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
    return value !== undefined && value !== null && value.length > 0 && value.indexOf(contains) !== -1;
  };

  /**
   * Checks whether a path is normalized (doesn't contain path traversal sequences like
   * "./", "/../" or "/.")
   * @param path the path to test
   * @return true if the path doesn't contain any path-traversal character sequences.
   */
  private isNormalized = (path: string): boolean => {
    if (path === undefined || path === null) {
      return true;
    }

    for (let i = path.length; i > 0; ) {
      let slashIndex = path.lastIndexOf('/', i - 1);
      let gap = i - slashIndex;
      if (gap === 2 && path.charAt(slashIndex + 1) === '.') {
        return false; // ".", "/./" or "/."
      }
      if (gap === 3 && path.charAt(slashIndex + 1) === '.' && path.charAt(slashIndex + 2) === '.') {
        return false;
      }
      i = slashIndex;
    }
    return true;
  };

  private rejectNonNormalizedRequests = async (req: Request): Promise<void> => {
    if (!this.isNormalizedRequest(req)) {
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
    const errorMessage = `The request was rejected because the URL contained a potentially malicious String ${req.url}`;
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
