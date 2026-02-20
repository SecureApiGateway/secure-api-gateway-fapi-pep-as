# Secure API Gateway FAPI PEP AS
This repo contains the fapi-pep-as Secure API Gateway component, this component builds on top of ForgeRock Identity Gateway
(IG) product to protect APIs to the [FAPI](https://fapi.openid.net/) standard.

## Gateway builds
### FAPI 1.0 Part 2 Advanced
This build creates a gateway capable of enforcing the following FAPI spec: https://openid.net/specs/openid-financial-api-part-2-1_0.html

The [configuration](config/7.3.0/fapi1part2adv) can be used as a starting point for a SAPI-G deployment protecting an OAuth2 Authorization
Server API using the aforementioned FAPI spec. 

The OAuth2 Resource Server(s) API protection is handled independently - see repo:
https://github.com/SecureApiGateway/secure-api-gateway-fapi-pep-rs-core

### FAPI 2.0
Support for [FAPI 2.0](https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html) is coming soon.

### Open Banking UK
A SAPI-G build exists for Open Banking UK, see repo: https://github.com/SecureApiGateway/secure-api-gateway-ob-uk

This build takes the fapi-pep-as and adds support for Open Banking UK API endpoints, protected with FAPI 1.0 Part 2 Advanced.

### Sub-modules
## secure-api-gateway-fapi-pep-as-docker
This module manages creating docker images for the gateway builds supported.

See [README.md](secure-api-gateway-core-docker/README.md) for more details.
