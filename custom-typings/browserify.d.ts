declare module "crypto-browserify" {
    export * from "crypto"
    import * as crypto from "crypto"
    
    export function createDiffieHellman(prime: string, encoding?: string): crypto.DiffieHellman;
}

declare module "querystring-es3" {
    export * from "querystring"
}