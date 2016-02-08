declare module XRDS {
    interface Service {
        priority: number;
        type: string;
        id: string;
        uri: string;
        delegate: string;
    }
    let parse: (data: string) => Service[];
}
export = XRDS;
