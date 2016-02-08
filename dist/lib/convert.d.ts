declare module Convert {
    let btwoc: (i: string) => string;
    let unbtwoc: (i: string) => string;
    let base64: {
        encode: (bin: string) => string;
        decode: (b64: string) => string;
    };
}
export = Convert;
