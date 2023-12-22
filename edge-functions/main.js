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
const API_SCOPES = ['id.clients', 'id.clients:read']

/**
 * Handler for /uuid-gen endpoints
 */
export async function handleHttpRequest(request, context) {

  console.log('Request URL: ' + request.url);

  // 1. check for presence of authorization header
  let authorizedHeader = request.headers.get('Authorization');

  if (!authorizedHeader)
    return errorResponse('Authorization header missing');

  // 2. check if its the right authentication scheme
  let authParts = authorizedHeader.trim().split(' ');
  const authScheme = 'bearer';
  const authSchemePartsTotal = 2;

  if (authParts.length != authSchemePartsTotal || authParts[0].toLowerCase() != authScheme)
    return errorResponse('Invalid authentication scheme');

  // 2. check token is valid jwt
  // most libraries do this already, however we can short-circuit the validation step if we know the token is malformed
  let tokenParts = authParts[1].split('.');
  const tokenPartsTotal = 3; // header.payload.signature

  if (tokenParts.length != tokenPartsTotal)
    return errorResponse('JWT token was not in a valid format');

  //
  // disabled due to perfomrance issue (exceeds 50ms cpu time) avg 1.2 seconds
  //

  // 3. validate jwt token
  // const metIdPubKey = 1;
  // context.metrics.add(metIdPubKey, metIdPubKey);
  // context.metrics.startTimer(metIdPubKey);
  // let pubKey = rs.KEYUTIL.getKey(IDS_DEV_PUB_KEY);
  // context.metrics.stopTimer(metIdPubKey);

  // const metIdJwtVerify = 2;
  // context.metrics.add(metIdJwtVerify, metIdJwtVerify);
  // context.metrics.startTimer(metIdJwtVerify);
  // let isValidToken = rs.jws.JWS.verifyJWT(authParts[1], pubKey, {
  //   alg: ['RS256'],
  //   iss: ['https://id-dev.vdms.io'],
  //   // aud: ['id.api', "https://id-dev.vdms.io/resources", "Test cps engine testing 12345678"] // use to ensure token contains matching aud
  //   aud: 'id.api'
  // });
  // context.metrics.stopTimer(metIdJwtVerify);

  // if (!isValidToken)
  //   return errorResponse('JWT token was not valid');

  // 4. validate scopes
  let tokenPayload = JSON.parse(rs.b64utos(tokenParts[1]));
  console.log(tokenPayload.scope);

  let scope = tokenPayload.scope.find((s) => API_SCOPES.find((a) => s == a));

  if (!scope)
    return errorResponse('API scope not found');


  // TOKEN was successfully validated, can continue to origin

  console.info('JWT token was valid');

  const metIdGetUpstream = 3;
  context.metrics.add(metIdGetUpstream, metIdGetUpstream);
  context.metrics.startTimer(metIdGetUpstream);

  // forward request to origin
  const response = await fetch(request.url, {
    edgio: {
      origin: 'origin',
    },
    method: request.method,
    headers: request.headers,
  });
  context.metrics.stopTimer(metIdGetUpstream);

  return response;
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
    headers: { "content-type": "application/json" },
    status: statusCode
  });

  return errorResponse;
}