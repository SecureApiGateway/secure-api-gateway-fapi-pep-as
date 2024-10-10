import static org.forgerock.util.promise.Promises.newResultPromise

SCRIPT_NAME = "[ASWellKnownFilter] "
logger.debug(SCRIPT_NAME + "Running...")

next.handle(context, request).thenAsync(response -> {
    if (response.status.isSuccessful()) {
        return response.entity.getJsonAsync().then(wellKnownData -> {
                    // Configure auth methods supported using filter arg: tokenEndpointAuthMethodsSupported
                    wellKnownData["token_endpoint_auth_methods_supported"] = tokenEndpointAuthMethodsSupported

                    // Update endpoints defined in mtlsEndpoints arg to use the mtls host
                    mtlsEndpoints.each { endpoint ->
                        wellKnownData[endpoint] = wellKnownData[endpoint].replace(igHost, mtlsHost)
                    }
                    response.entity.setJson(wellKnownData)
                    return response
        })
    }
    return newResultPromise(response)
})
