import * as http from 'http';
declare module OpenID {
    type EncryptionAlgorithms = "DH-SHA256" | "DH-SHA1" | "no-encryption-256" | "no-encryption";
    type HashingAlgorithms = "sha256" | "sha1";
    type StringDict = {
        [index: string]: string;
    };
    type RequestOrUrl = http.IncomingMessage | string;
    class RelyingParty {
        returnUrl: string;
        realm: string;
        stateless: boolean;
        strict: boolean;
        extensions: OpenIDExtension[];
        constructor(returnUrl: string, realm: string, stateless: boolean, strict: boolean, extensions?: OpenIDExtension[]);
        authenticate(identifier: string, immediate: boolean, callback: (error?: {
            message: string;
        }, result?: string) => void): void;
        verifyAssertion(requestOrUrl: RequestOrUrl, callback: (error?: {
            message: string;
        }, result?: {
            authenticated: boolean;
            claimedIdentifier?: string;
        }) => void): void;
    }
    interface OpenIDProviderAssociation {
        provider: OpenIDProvider;
        type: HashingAlgorithms;
        secret: string;
    }
    let saveAssociation: (provider: OpenIDProvider, type: "sha256" | "sha1", handle: string, secret: string, expiry_time_in_seconds: number, callback: (err: void) => void) => void;
    let loadAssociation: (handle: string, callback: (err: void, res: OpenIDProviderAssociation) => void) => void;
    let removeAssociation: (handle: string) => boolean;
    let saveDiscoveredInformation: (key: string, provider: OpenIDProvider, callback: (err: any) => void) => void;
    let loadDiscoveredInformation: (key: string, callback: (err: any, res: OpenIDProvider) => void) => void;
    interface OpenIDProvider {
        endpoint?: string;
        claimedIdentifier?: string;
        version?: string;
        localIdentifier?: string;
    }
    let discover: (identifier: string, strict: boolean, callback: (error?: {
        message: string;
    }, providers?: OpenIDProvider[]) => void) => void;
    let associate: (provider: OpenIDProvider, callback: (error?: any, result?: any) => void, strict?: boolean, algorithm?: "DH-SHA256" | "DH-SHA1" | "no-encryption-256" | "no-encryption") => void;
    let authenticate: (identifier: string, returnUrl: string, realm: string, immediate: boolean, stateless: boolean, callback: (error?: {
        message: string;
    }, result?: string) => void, extensions: OpenIDExtension[], strict: boolean) => void;
    let verifyAssertion: (requestOrUrl: http.IncomingMessage | string, originalReturnUrl: string, callback: (error?: {
        message: string;
    }, result?: {
        authenticated: boolean;
        claimedIdentifier?: string;
    }) => void, stateless: boolean, extensions: OpenIDExtension[], strict: boolean) => void;
    interface OpenIDExtension {
        fillResult(params: any, result: any): void;
        requestParams: StringDict;
    }
    class SimpleRegistration implements OpenIDExtension {
        requestParams: StringDict;
        constructor(options: {
            [index: string]: any;
        });
        fillResult(params: StringDict, result: StringDict): void;
    }
    class UserInterface implements OpenIDExtension {
        requestParams: StringDict;
        constructor(options: {
            [index: string]: any;
        });
        fillResult(params: StringDict, result: StringDict): void;
    }
    class AttributeExchange implements OpenIDExtension {
        requestParams: StringDict;
        constructor(options: {
            [index: string]: any;
        });
        fillResult(params: StringDict, result: StringDict): void;
    }
    class OAuthHybrid implements OpenIDExtension {
        requestParams: StringDict;
        constructor(options: StringDict);
        fillResult(params: StringDict, result: StringDict): void;
    }
    class PAPE implements OpenIDExtension {
        requestParams: StringDict;
        constructor(options: StringDict);
        fillResult(params: StringDict, result: StringDict): void;
    }
}
export = OpenID;
