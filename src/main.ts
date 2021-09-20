import fs from 'fs';
import jsrsasign from 'jsrsasign';

let dateHeaderValue: string | undefined = undefined;

// Creates a token tag with the required parameters for OCI API token creation.
const tokenTag = {
    name: 'oci_bearer_token',
    displayName: 'OCI Auth Token',
    description: 'Generate a bearer token for OCI authentication requests',
    args: [
        {
            displayName: 'API Version',
            type: 'string',
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
    async run (context: any, apiVer: string, tenancyId: string, userId: string, keyFingerprint: string, privKeyPath: string) {
        // console.log('[oci-auth-provider]', 'get oci_bearer_token')
        // console.log('[oci-auth-provider]', apiVer)
        // console.log('[oci-auth-provider]', tenancyId)
        // console.log('[oci-auth-provider]', userId)
        // console.log('[oci-auth-provider]', keyFingerprint)
        // console.log('[oci-auth-provider]', privKeyPath)
        // console.log('[oci-auth-provider]', context);

        const privKey = fs.readFileSync(privKeyPath, 'utf-8');

        const { meta }: any = context;

        if (!meta.requestId || !meta.workspaceId) {
            return null;
        }

        const request = await context.util.models.request.getById(meta.requestId);
        console.log(request);

        const method = request.method;
        let body = request.body;
        let headersToSign = [
            "date",
            "(request-target)",
            "host"
        ];

        const methodsThatRequireExtraHeaders = [ "POST", "PUT" ];
        if (methodsThatRequireExtraHeaders.indexOf(method.toUpperCase()) !== -1) {
            headersToSign = headersToSign.concat([
                "content-length",
                "content-type",
                "x-content-sha256"
            ]);
        }

        const hostname = request.url.replace(/(http|https)\:\/\/([a-zA-Z0-9\.\-_]+)\/.*/gi, "$2");
        const urlPath = request.url.replace(/(http|https)\:\/\/[a-zA-Z0-9\.\-_]+/gi, "");

        console.log(`[oci-auth-provider] hostname: ${hostname}`);
        console.log(`[oci-auth-provider] urlPath: ${urlPath}`);

        // Set the date header to current time
        const now = new Date();
        dateHeaderValue = now.toUTCString();
        request.headers.push({
            name: 'date',
            value: dateHeaderValue
        });

        // if x-date and date are included, then drop the date header
        if (request.headers.find((element: any, index: number) => {
            return element.name.toLowerCase() === 'x-date' && !element.disabled;
        })) {
            headersToSign[ 0 ] = "x-date";
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

					const parameters = request.parameters;

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

                    console.log(`[oci-auth-provider] request-target: ${requestTarget}`);

					signingStr += requestTarget;
                    break;
                case "content-length":
                    signingStr += header + ": " + body.length;
                    console.log(`[oci-auth-provider] content-length: ${body.length}`);
                    break;
                case "host":
                    signingStr += header + ": " + hostname;
                    console.log(`[oci-auth-provider] host: ${hostname}`);
                    break;
                default:
                    console.log(`[oci-auth-provider] Attept to get header ${header}`);
                    const headerObj = request.headers.find((element: any, index: number) => {
                        return element.name.toLowerCase() === header.toLowerCase() && !element.disabled;
                    });
                    console.log(headerObj)
                    if (headerObj && typeof (headerObj.value) === "string") {
                        console.log(`[oci-auth-provider] Header ${headerObj.name}: ${headerObj.value}`);
                        signingStr += headerObj.name + ": " + headerObj.value;
                    } else {
                        throw new Error("Required header has no value: " + header);
                    }
                    break;
            }
        }

        // initialize
        
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

        return dynamicValue;
    }
};

// Sets the date header on request to match the calculated value in the token tag.
const requestHook = async function (context: any) {
    const dateHeader = await context.request.getHeader('date');
    const xDateHeader = await context.request.getHeader('x-date');

    if(!dateHeader && !xDateHeader) {
        console.log(`[oci-auth-provider] Setting date header to value: ${dateHeaderValue}`);
        await context.request.setHeader('date', dateHeaderValue);
    }
};

module.exports = {
    templateTags: [ tokenTag ],
    requestHooks: [ requestHook ]
};

console.log('[oci-auth-provider]', 'plugin loaded');