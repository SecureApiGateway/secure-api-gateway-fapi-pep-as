import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.store.JwksStore.*
import org.forgerock.json.JsonValueFunctions.*


import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import java.security.PrivateKey

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.JWKSet

import groovy.json.JsonOutput

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[JwkmsSignClientClaims] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

logger.debug(SCRIPT_NAME + "Signing claims as ApiClient")

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

def getSigKey(jwks) {
    List<RSAKey> jwkKeys = jwks.getKeys();

    def key = null;

    jwkKeys.forEach(k -> {
    def use = k.getKeyUse().identifier();
    logger.debug(SCRIPT_NAME + "Key use " + use);
    if (use == "sig") {
        logger.debug(SCRIPT_NAME + "Found signing key " + k);
        key = k;
    }
});

    return key;
}

def requestObject = request.entity.getJson();

if (!requestObject) {
    message = "Couldn't parse request JSON"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

if (!requestObject.claims) {
    message = "No claims payload in request"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

if (!requestObject.jwks) {
    message = "No jwks in request"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

JWKSet jwks = JWKSet.parse(JsonOutput.toJson(requestObject.jwks));

if (!jwks) {
    message = "Couldn't parse request body as JWK set"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

RSAKey jwk = getSigKey(jwks);

if (!jwk) {
    message = "Couldn't find signing key in JWK set"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

PrivateKey privateKey = jwk.toPrivateKey();

if (!privateKey) {
    message = "Couldn't find private key in sig jwk"
    logger.error(SCRIPT_NAME + message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}


def kid = jwk.getKeyID();
def claimSet = new JwtClaimsSet(requestObject.claims)

SigningHandler signingHandler = new SigningManager().newRsaSigningHandler(privateKey);

def jwt = new JwtBuilderFactory()
        .jws(signingHandler)
        .headers()
        .alg(JwsAlgorithm.PS256)
        .kid(kid)
        .done()
        .claims(claimSet)
        .build();

logger.debug(SCRIPT_NAME + "Generated jwt {}", jwt)

Response response = new Response(Status.OK)
response.getHeaders().add("Content-Type","text/plain");
response.setEntity(jwt);

return response
