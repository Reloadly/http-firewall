import {NextFunction, Request, Response} from "express";

export type PredicateType<T> = (x: T) => boolean;

export class Predicate<T> {
    constructor(private condition: PredicateType<T>) {}

    private static isInstance = <T>(input: Predicate<T> | PredicateType<T>): Predicate<T> => (input instanceof Predicate) ? input : Predicate.of(input);

    public static of = <T>(condition: PredicateType<T>) => new Predicate(condition);

    public and = (input: Predicate<T> | PredicateType<T>): Predicate<T> =>
        Predicate.of((x: T) => this.test(x) && Predicate.isInstance(input).test(x));

    public or = (input: Predicate<T> | PredicateType<T>): Predicate<T> =>
        Predicate.of((x: T) => this.test(x) || Predicate.isInstance(input).test(x));

    public not = (): Predicate<T> =>
        Predicate.of((x: T) => !this.test(x));

    public test = (x: T): boolean => this.condition(x);
}

export declare type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'TRACE';

export interface HttpFirewallOptions {
    unsafeAllowAnyHttpMethod?: boolean;
    allowedHttpMethods?: HttpMethod[];
    allowSemicolon?:boolean;
    allowUrlEncodedSlash?: boolean;
    allowUrlEncodedDoubleSlash?: boolean;
    allowUrlEncodedPeriod?: boolean;
    allowBackSlash?:boolean;
    allowNull?: boolean;
    allowUrlEncodedPercent?: boolean;
    allowUrlEncodedCarriageReturn?: boolean;
    allowUrlEncodedLineFeed?: boolean;
    allowUrlEncodedParagraphSeparator?: boolean;
    allowUrlEncodedLineSeparator?: boolean;
    allowedHeaderNames?: Predicate<string>;
    allowedHeaderValues?: Predicate<string>;
    allowedParameterNames?: Predicate<string>;
    allowedParameterValues?: Predicate<string>;
    allowedHostnames: Predicate<string>;

}
export interface HttpFirewall {
    firewall: (req: Request, res: Response, next: NextFunction) => void ;
}
