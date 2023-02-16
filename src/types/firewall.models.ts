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

  // noinspection JSUnusedGlobalSymbols
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

  /**
   * A list of strings that are considered malicious in URLs. If these strings are found in the request URL, the
   * request will be rejected.
   */
  decodedUrlBlockList?: string[];

  /**
   * A list of strings that are considered malicious in encoded URLs. If these strings are found in the request URL, the
   * request will be rejected.
   */
  encodedUrlBlockList?: string[];
}
