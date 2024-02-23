SCRIPT_NAME = "[ASWellKnownFilter] "
logger.debug(SCRIPT_NAME + "Running...")

next.handle(context, request).thenOnResult(response -> {
    if (response.status.isSuccessful()) {
        wellKnownData = response.entity.getJson()
        // Configure auth methods supported using filter arg: tokenEndpointAuthMethodsSupported
        wellKnownData["token_endpoint_auth_methods_supported"] = tokenEndpointAuthMethodsSupported

        // Configure jwks_uri if arg is present
        if (jwksUri) {
            wellKnownData["jwks_uri"] = jwksUri
        }

        // Update endpoints defined in mtlsEndpoints arg to use the mtls host
        mtlsEndpoints.each { endpoint ->
            wellKnownData[endpoint] = wellKnownData[endpoint].replace(igHost, mtlsHost)
        }
        response.entity.setJson(wellKnownData)
    }
})
