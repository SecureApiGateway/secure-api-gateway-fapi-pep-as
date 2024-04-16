# Secure API Gateway Core
This repo contains the core Secure API Gateway component, this component builds on top of ForgeRock Identity Gateway
(IG) product to protect APIs to the [FAPI](https://fapi.openid.net/) standard.

## Gateway builds
### FAPI 1.0 Part 2 Advanced
This build creates a gateway capable of enforcing the following FAPI spec: https://openid.net/specs/openid-financial-api-part-2-1_0.html

The [configuration](config/7.3.0/fapi1part2adv) can be used as a starting point for a SAPI-G deployment which protects 
any API using the aforementioned FAPI spec.

The [01-rs-example-fapi-protected-api.json](config/7.3.0/fapi1part2adv/ig/routes/routes-service/01-rs-example-fapi-protected-api.json)
route acts as an example API endpoint which provides enough functional to enable the OIDF FAPI conformance suite (https://openid.net/certification/certification-fapi_op_testing/)
to test a deployment. In a real world deployment, one or more RS (Resource Server) routes will be used in its place 
which reverse proxy upstream services providing the real functionality.

### FAPI 2.0
Support for [FAPI 2.0](https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html) is coming soon.

### Open Banking UK
A SAPI-G build exists for Open Banking UK, see repo: https://github.com/SecureApiGateway/secure-api-gateway-ob-uk

This build takes the core and adds support for Open Banking UK API endpoints, protected with FAPI 1.0 Part 2 Advanced.

### Sub-modules
## secure-api-gateway-core-docker
This module manages creating docker images for the gateway builds supported.

See [README.md](secure-api-gateway-core-docker/README.md) for more details.

## secure-api-gateway-ig-extensions module
This module contains Java code which extends the functionality of the ForgeRock Identity Gateway (IG) product.

See [README.md](secure-api-gateway-ig-extensions/README.md) for more details.