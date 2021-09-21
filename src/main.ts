import fs from 'fs';
import jsrsasign from 'jsrsasign';

let apiVer: string | undefined;
let tenancyId: string | undefined;
let userId: string | undefined;
let keyFingerprint: string | undefined;
let privKeyPath: string | undefined;

// Creates a token tag with the required parameters for OCI API token creation.
const tokenTag = {
    name: 'oci_auth_signature',
    displayName: 'OCI Auth Signature',
    description: 'Generate a signature for OCI authentication requests',
    disablePreview: () => { return false },
    args: [
        {
            displayName: 'API Version',
            type: 'enum',
            options: [
                {
                    displayName: 'Version 1',
                    value: '1'
                }
            ]
        },
        {
            displayName: 'Tenancy ID',
            type: 'string',
            placeholder: 'ocid1.tenancy.oc1..aaaaaaaap______keq'
        },
        {
            displayName: 'User ID',
            type: 'string',
            placeholder: 'ocid1.user.oc1..aaaaaaaas______7ap'
        },
        {
            displayName: 'Public Key Fingerprint',
            type: 'string',
            placeholder: 'd1:b2:32:53:d3:5f:cf:68:2d:6f:8b:5f:77:8f:07'
        },
        {
            displayName: 'Private Key Path',
            type: 'string',
            placeholder: '/Users/scott/.oci/my_key.pem'
        }
    ],
    async run(context: any, ...args: any[]) {
        console.log(context);
        console.log(args);

        apiVer = args[0];
        tenancyId = args[1];
        userId = args[2];
        keyFingerprint = args[3];
        privKeyPath = args[4];

        return "Value calculated when request is run.";
    }
};

// Sets the date header on request to match the calculated value in the token tag.
const requestHook = async function (context: any) {
    const signature = await calculateSignature(context.request);
    context.request.setHeader('Authorization', signature);
};

const calculateSignature = function (request: any): Promise<string> {
    return new Promise(async (resolve, reject) => {
        if (!apiVer) {
            reject("API version not set");
        }
        if (!tenancyId) {
            reject("Tenancy ID not set");
        }
        if (!userId) {
            reject("User ID not set");
        }
        if (!keyFingerprint) {
            reject("Public key fingerprint not set");
        }
        if (!privKeyPath) {
            reject("Private key path not set");
        }

        const url = await request.getUrl();
        const hostname = url.replace(/(http|https)\:\/\/([a-zA-Z0-9\.\-_]+)\/.*/gi, "$2");
        const urlPath = url.replace(/(http|https)\:\/\/[a-zA-Z0-9\.\-_]+/gi, "");
        const method = await request.getMethod();
        const body = await request.getBody();

        let headersToSign = [
            "date",
            "(request-target)",
            "host"
        ];

        const methodsThatRequireExtraHeaders = ["POST", "PUT"];
        if (methodsThatRequireExtraHeaders.indexOf(method.toUpperCase()) !== -1) {
            headersToSign = headersToSign.concat([
                "content-length",
                "content-type",
                "x-content-sha256"
            ]);
        }

        console.log(`[oci-auth-signature] hostname: ${hostname}`);
        console.log(`[oci-auth-signature] urlPath: ${urlPath}`);

        const dateHeader = await request.getHeader('date');
        const xDateHeader = await request.getHeader('x-date');

        if (!dateHeader && !xDateHeader) {
            const now = new Date();
            const utcDate = now.toUTCString();
            console.log(`[oci-auth-signature] Setting date header to value: ${utcDate}`);
            await request.setHeader('date', utcDate);
        }

        // if x-date and date are included, then drop the date header
        const allHeaders = await request.getHeaders();
        if (allHeaders.find((header: any) => {
            return header.name.toLowerCase() === 'x-date';
        })) {
            headersToSign[0] = "x-date";
        }

        const apiKeyId = `${tenancyId}/${userId}/${keyFingerprint}`;

        let signingStr = "";

        for (const header of headersToSign) {
            if (signingStr.length > 0) {
                signingStr += "\n";
            }

            switch (header) {
                case "(request-target)":
                    let requestTarget = "(request-target): " + method.toLowerCase() + " " + urlPath;

                    const parameters = await request.getParameters();

                    if (parameters !== undefined && parameters.length > 0) {
                        let queryStr = "?";
                        let index = 0;
                        for (const param of parameters) {
                            const val = encodeURIComponent(param.value);
                            queryStr += index > 0 ? "&" : "";
                            queryStr += param.name + "=" + val;
                            index++;
                        }

                        requestTarget += queryStr;
                    }

                    console.log(`[oci-auth-signature] request-target: ${requestTarget}`);

                    signingStr += requestTarget;
                    break;
                case "content-length":
                    signingStr += header + ": " + body.length;
                    console.log(`[oci-auth-signature] content-length: ${body.length}`);
                    break;
                case "host":
                    signingStr += header + ": " + hostname;
                    console.log(`[oci-auth-signature] host: ${hostname}`);
                    break;
                default:
                    console.log(`[oci-auth-signature] Attept to get header ${header}`);
                    const headerVal = request.getHeader(header);
                    if (headerVal) {
                        console.log(`[oci-auth-signature] Header ${header}: ${headerVal}`);
                        signingStr += header + ": " + headerVal;
                    } else {
                        reject("Required header has no value: " + header);
                    }
                    break;
            }
        }

        console.log(`[oci-auth-signature] Singing string:\n${signingStr}`)

        const privKey = fs.readFileSync(privKeyPath!, 'utf-8');

        const sig = new jsrsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
        // initialize for signature validation
        const key = jsrsasign.KEYUTIL.getKey(privKey);
        sig.init(key);
        // update data
        sig.updateString(signingStr);
        // calculate signature
        const sigValueHex = sig.sign();

        // convert signature hex to base64
        const base64Sig = jsrsasign.hextob64(sigValueHex);
        const headersStr = headersToSign.join(" ");

        // finish constructing the Authorization header with the signed signature
        const dynamicValue = `Signature version="${apiVer}",headers="${headersStr}",keyId="${apiKeyId}",algorithm="rsa-sha256",signature="${base64Sig}"`;

        console.log(`[oci-auth-signature] Calculated signature:\n${dynamicValue}`)

        resolve(dynamicValue);
    });
};

module.exports = {
    templateTags: [tokenTag],
    requestHooks: [requestHook]
};

console.log('[oci-auth-signature]', 'plugin loaded');