import * as signature from "../src/main";

const testApiVer = "1";
const testTenant = "ocid1.tenancy.oc1..test";
const testUser = "ocid1.user.oc1..test";
const testKeySig = "73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7";
const testKey = "./__tests__/assets/test_priv.key";
const testDate = "Thu, 05 Jan 2014 21:31:40 GMT";

describe("Signature Calculations", () => {
    let context: any;
    let request: any;

    beforeEach(async () => {
        request = {
            method: "",
            headers: [],
            body: {
                text: ""
            },
            url: "https://iaas.us-ashburn-1.oraclecloud.com/20160918/vcns",

            getMethod: () => {
                return request.method;
            },

            getBody: () => {
                return request.body;
            },

            setHeader: (name: string, value: any) => {
                const header = {
                    name: name,
                    value: value
                };

                if (!request.headers.find((element, index) => {
                    if (element.name === name) {
                        request.headers[index] = header;
                    }

                    return false;
                })) {
                    request.headers.push(header);
                }
            },

            getHeader: (name: string): string | undefined => {
                const header = request.headers.find(element => {
                    return element.name === name;
                });

                return header ? header.value : undefined;
            },

            getHeaders: (): string[] => {
                return request.headers;
            },

            hasHeader: (name: string): boolean => {
                return request.headers.hasOwnProperty(name);
            },

            getUrl: (): string => {
                return request.url;
            },

            getParameters: (): string[] | undefined => {
                return request.parameters;
            }
        };

        context = {
            request: request
        };

        const runRes = await signature.tokenTag.run({}, testApiVer, testTenant, testUser, testKeySig, testKey);

        expect(runRes).toBe("Value calculated when request is run.");
    });

    test("it should set date header when `date` variable is used", async () => {
        const method = "GET";
        context.request.method = method;
        await context.request.setHeader('date', testDate);
        await signature.setHeaders(context.request);

        expect(context.request.getHeader('date')).toBe(testDate);
        expect(context.request.getMethod()).toBe(method);
    });

    test("it should set x-date header when `x-date` variable is used", async () => {
        const method = "GET";
        context.request.method = method;
        await context.request.setHeader('x-date', testDate);
        await signature.setHeaders(context.request);

        expect(context.request.getHeader('x-date')).toBe(testDate);
        expect(context.request.getMethod()).toBe(method);
    });

    test("it should set x-date header when no date variable is used", async () => {
        const method = "GET";
        context.request.method = method;
        await signature.setHeaders(context.request);

        expect(context.request.getHeader('x-date')).toBeDefined(); // Will be set to current date so only check for existence.
        expect(context.request.getMethod()).toBe(method);
    });

    test("it should set calculated headers on the request object for POST", async () => {
        const method = "POST";
        context.request.method = method;
        await context.request.setHeader('x-date', testDate);
        await signature.setHeaders(context.request);

        expect(context.request.getHeader('x-date')).toBe(testDate);
        expect(context.request.getMethod()).toBe(method);
    });

    test("it should set calculated headers on the request object for PUT", async () => {
        const method = "PUT";
        context.request.method = method;
        await context.request.setHeader('x-date', testDate);
        await signature.setHeaders(context.request);

        expect(context.request.getHeader('x-date')).toBe(testDate);
        expect(context.request.getMethod()).toBe(method);
    });

    test("it should set calculated headers on the request object for DELETE", async () => {
        const method = "DELETE";
        context.request.method = method;
        await context.request.setHeader('x-date', testDate);
        await signature.setHeaders(context.request);

        expect(context.request.getHeader('x-date')).toBe(testDate);
        expect(context.request.getMethod()).toBe(method);
    });

    test("it should calculate and return an expected signature string for GET", async () => {
        const method = "GET";
        const expectedSignature = 'Signature version="1",headers="x-date (request-target) host",keyId="ocid1.tenancy.oc1..test/ocid1.user.oc1..test/73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7",algorithm="rsa-sha256",signature="uFeCXLF/uJWclkyhNJhNvSGlTevqhkpboE6LdSDdXsEdz2KhVnIjqx21W138M1tDmVzUOKKSIwHlzbsZmDQDu3zyo9RyL6xANoWWF+iUUGw7UrHGKzKMC0nuogy06VzuBL4RqkNyvmcaKMPGu400SFqsAAeHRvRmrVZ5weuu1WE="';

        context.request.method = method;
        await context.request.setHeader('x-date', testDate);
        await signature.setHeaders(context.request);
        const calcultedSig = await signature.calculateSignature(context.request);

        expect(calcultedSig).toBe(expectedSignature);
    });

    test("it should calculate and return an expected signature string for POST", async () => {
        const method = "POST";
        const expectedSignature = 'Signature version="1",headers="x-date (request-target) host content-length content-type x-content-sha256",keyId="ocid1.tenancy.oc1..test/ocid1.user.oc1..test/73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7",algorithm="rsa-sha256",signature="NL8/L4SUKgxk5ogLl+VFWj5scUZdaRdJp/4sN2eE2IhbroJKBsHp+N8Pmxa2zLlPwKpgBDkce7zSz/JtTDXpI8EkcCSB/wEk2U9BdVxPLerpXHVuvBxsTMmiliKHLEKdFPXOT1ityfXGkG3BerEM0DUEsUlnzfIAtboP21hLBwo="';

        context.request.method = method;
        context.request.body.text = "\"{'val': '1', 'another': 2 }\"";
        await context.request.setHeader('x-date', testDate);
        await context.request.setHeader('Content-Type', 'application/json');
        await signature.setHeaders(context.request);
        const calcultedSig = await signature.calculateSignature(context.request);

        expect(calcultedSig).toBe(expectedSignature);
    });

    test("it should calculate and return an expected signature string for PUT", async () => {
        const method = "PUT";
        const expectedSignature = 'Signature version="1",headers="x-date (request-target) host content-length content-type x-content-sha256",keyId="ocid1.tenancy.oc1..test/ocid1.user.oc1..test/73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7",algorithm="rsa-sha256",signature="CttdXxmLwoJHWfHKkm1EaNo7pFHyyeI+SoFl+6jqW+kN3NpOW43GHhuXp4IUtHm6CcQKQ1dR9Luw57JfdsuPkZXcIQ9RUttcoEM+ewD69UxT3BW/GTbIKtk3kG4BZkI1beytnAwgnLgWkfZH+uncvzmvHosaPwpM3kELYl1Cytk="';

        context.request.method = method;
        context.request.body.text = "\"{'val': '1', 'another': 2 }\"";
        await context.request.setHeader('x-date', testDate);
        await context.request.setHeader('Content-Type', 'application/json');
        await signature.setHeaders(context.request);
        const calcultedSig = await signature.calculateSignature(context.request);

        expect(calcultedSig).toBe(expectedSignature);
    });

    test("it should calculate and return an expected signature string for DELETE", async () => {
        const method = "DELETE";
        const expectedSignature = 'Signature version="1",headers="x-date (request-target) host",keyId="ocid1.tenancy.oc1..test/ocid1.user.oc1..test/73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7",algorithm="rsa-sha256",signature="PMduuq2fpmXwWVIxJVrt3T3rMlvpx1wsw3yVDQ/eGclb5qXvomLg4MfTbKaygA3LA1sGOZNAWKGpPtmt53l2X6YPIhWEwZ8UpwsznhmjGezH709Vh/5dFWcVWH19lX+5mvDY3IIQ+GmKr96+lRnwfbwH/EEdDVPaAEAN0F/+/dw="';

        context.request.method = method;
        await context.request.setHeader('x-date', testDate);
        await signature.setHeaders(context.request);
        const calcultedSig = await signature.calculateSignature(context.request);

        expect(calcultedSig).toBe(expectedSignature);
    });

    test("it should call the requestHook method without error", async () => {
        const method = "GET";
        await context.request.setHeader('x-date', testDate);
        await expect(signature.requestHook(context)).not.toThrowError;
    });
});