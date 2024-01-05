const rs = require('jsrsasign');

/**
 * Public JWKS needed for jwt verification.
 * https://id-dev.vdms.io/.well-known/openid-configuration/jwks
 * keys[0]
 */
const IDS_DEV_PUB_KEY = {
  "kty": "RSA",
  "use": "sig",
  "kid": "2729EF68161B1FAD52B3156238BF61F1730B6971",
  "x5t": "JynvaBYbH61SsxViOL9h8XMLaXE",
  "e": "AQAB",
  "n": "29wdnjwuGFl-5IcxWnkRdB8oU5g3ebAs-I5EBwO0dxr8T5oRltDSbuN2bgZZjGz3EXilUkFqkPV6-X4IL9UpJu1dMUEIuw_AswnCiGcnUf6sjWGRiRSCzixfvdld1avzBRDXItnquYgdkJsZewehVAKs5VkQZGcPyyF-WLQgf1aK0ZN-YP3ZQlMRt4PgMLpjZ0HB-1S6Zxfd5izV34ww259e7BEWlRaZfXPaIylmW29UuQbFUUMU7wzqcCO1sOeW3VDW8hstT0nEzieYbsIp00KGDkK7qzeQxuyrNFiULIxeANKyfmnIbOrswtgpDn7b0KxDVX5sMzBz3EHGQpDU4w",
  "x5c": [
    "MIIDlTCCAn2gAwIBAgIJAIiZ7x36j54tMA0GCSqGSIb3DQEBCwUAMGExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRQwEgYDVQQHDAtQbGF5YSBWaXN0YTEnMCUGA1UECgweVmVyaXpvbiBEaWdpdGFsIE1lZGlhIFNlcnZpY2VzMB4XDTE3MDQyOTAzMzE0OFoXDTE3MDUyOTAzMzE0OFowYTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAcMC1BsYXlhIFZpc3RhMScwJQYDVQQKDB5WZXJpem9uIERpZ2l0YWwgTWVkaWEgU2VydmljZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDb3B2ePC4YWX7khzFaeRF0HyhTmDd5sCz4jkQHA7R3GvxPmhGW0NJu43ZuBlmMbPcReKVSQWqQ9Xr5fggv1Skm7V0xQQi7D8CzCcKIZydR/qyNYZGJFILOLF+92V3Vq/MFENci2eq5iB2Qmxl7B6FUAqzlWRBkZw/LIX5YtCB/VorRk35g/dlCUxG3g+AwumNnQcH7VLpnF93mLNXfjDDbn17sERaVFpl9c9ojKWZbb1S5BsVRQxTvDOpwI7Ww55bdUNbyGy1PScTOJ5huwinTQoYOQrurN5DG7Ks0WJQsjF4A0rJ+achs6uzC2CkOftvQrENVfmwzMHPcQcZCkNTjAgMBAAGjUDBOMB0GA1UdDgQWBBT2tO7LI6Shmzazx7LFfcaoO+58FjAfBgNVHSMEGDAWgBT2tO7LI6Shmzazx7LFfcaoO+58FjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB6xz7L40fDC/vV1reAysu9TLbP3ngnYRxVt9RnQ3Akb6WiXcafHySSuyOgqcH09AsdQlAy8eb2SKr7GHklHxnVZsNGcNzrv57zrJedL9wyRB7Bgi2L7KOQ5N9WnctTQHeCBLn/TGtAkAy7xnru94bIKsaRX+LtPZ1X7N/qwif/ZvaAuVYBNHWTGAmR3NGkKrN5wRTMt+4j2DTFxT/Moh98TI+e2WwfqoPGCJxdfk7ZrIT+5S4sl7tPa40Uygt2VeDKANJa1GtuukhQ1ZJwGquyQIvTeghtkmoP+NXXfgvPGbDlsuNS63Rp+Hs4v5Mss5hCDJelmQHLCRg0C5rforpT"
  ],
  "alg": "RS256"
};

/**
 * API scopes this endpoint accepts
 */
const API_SCOPES = ['id.clients']

/**
 * Handler for /uuid-gen endpoints
 */
export async function handleHttpRequest(request, context) {
  console.log('Request URL: ' + request.url);

  const env = context.environmentVars;

  // extract token from authorization header
  var jwtToken = extractBearerToken(request.headers);
  if (jwtToken == null)
    return errorResponse('Token is missing or is not valid');

  let isValid = await isValidJwtTokenAuthServer(env.IDP_URL, env.INTROSPECT_SECRET,
    jwtToken, API_SCOPES);

  if (!isValid)
    return errorResponse('Token is missing or is not valid');

  // token was successfully validated, can continue to origin
  console.info('JWT token was valid');

  // forward request to origin API
  const originResponse = await fetch(request.url, {
    edgio: {
      origin: 'api-origin',
    },
    method: 'GET'
  });

  // return custom response
  let originResponseData = await originResponse.text();
  let hyperionData = {
    '@id': '/v1/uuid-gen',
    '@Type': 'Uuid',
    'uuid': originResponseData
  };

  const content = JSON.stringify(hyperionData);
  const response = new Response(content, {
    headers: { 'content-type': 'application/json' },
    status: 200
  });

  return response;
}

/**
 * Extracts the bearer token value from the authorization header.
 */
function extractBearerToken(requestHeaders) {
  // 1. check for presence of authorization header
  let authorizedHeader = requestHeaders.get('Authorization');

  if (!authorizedHeader) {
    console.log('Authorization header missing');
    return null;
  }

  // 2. check if its the right authentication scheme
  let authParts = authorizedHeader.trim().split(' ');
  const authScheme = 'bearer';
  const authSchemePartsTotal = 2;

  if (authParts.length != authSchemePartsTotal || authParts[0].toLowerCase() != authScheme) {
    console.log('Invalid authentication scheme');
    return null;
  }

  return authParts[1];
}

/**
 * Validates a JWT token using pure javascript.
 * - Currently not usable in EF due to native crypto libraries not
 * available in runtime.
 */
function isValidJwtTokenNonNative(idpUrl, token, scopes) {

  // 1. get public certificate information used to sign the token
  let pubKey = rs.KEYUTIL.getKey(IDS_DEV_PUB_KEY);

  // 2. verify token
  let isValidToken = rs.jws.JWS.verifyJWT(token, pubKey, {
    alg: ['RS256'],
    iss: [idpUrl],
    aud: 'id.api'
  });

  if (!isValidToken) {
    console.log('JWT token was not valid')
    return false;
  }

  // 3. validate scopes
  let tokenParts = token.split('.');
  const tokenPartsTotal = 3; // header.payload.signature

  if (tokenParts.length != tokenPartsTotal) {
    console.log('JWT token was not in a valid format');
    return false;
  }

  // decode the json payload from token 
  let tokenPayload = JSON.parse(rs.b64utos(tokenParts[1]));
  console.log('Scopes in token: ' + tokenPayload.scope);

  // check if scopes exist
  let scope = tokenPayload.scope.find((s) => scopes.find((a) => s == a));

  if (!scope) {
    console.log('Scope not found in token')
    return false;
  }

  return true;
}

/**
 * Offloads token check using an outbound API call to IdP introspect endpoint.
 */
async function isValidJwtTokenAuthServer(idpUrl, introspectSecret, token, scopes) {

  console.log('IdP URL from env: ' + idpUrl)

  let response = await fetch(idpUrl + '/connect/introspect', {
    edgio: {
      origin: 'ids-origin',
    },
    body: 'token=' + token,
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + introspectSecret,
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });

  let responseData = await response.json();

  if (!responseData.active) {
    console.log('Token not valid');
    return false;
  }

  // check if scopes exist
  let tokenScopes = responseData.scope.split(' ');
  let scope = tokenScopes.find((s) => scopes.find((a) => s == a));

  if (!scope) {
    console.log('Scope not found in token')
    return false;
  }

  return true;
}

/**
 * Default error wrapper.
 */
function errorResponse(errorDescription) {
  const statusCode = 401;

  let data = {
    '@type': 'Error',
    'code': 'unauthorized',
    'status_code': statusCode,
    'title': 'You are not authorized to access this resource'
  };

  if (errorDescription)
    data.description = errorDescription;

  const content = JSON.stringify(data);

  const errorResponse = new Response(content, {
    headers: { 'content-type': 'application/json' },
    status: statusCode
  });

  return errorResponse;
}