# Secure API Gateway IG Docker Image
The Secure API Gateway Docker image extends the IG base image, adding Secure API Gateway code and config.

## Building the image
The [Makefile](../Makefile) is used to build the image

The `tag` argument can be supplied to tag the image, this is defaulted to latest.

Example command:
```
make clean docker tag=my-new-image
```

## Docker image contents
- IG configuration
- IG routes
- Extension groovy scripts
- Java libraries required by the groovy scripts and routes
    - These dependencies are captured in the [pom.xml](./pom.xml) in this module
    - Libraries used by Groovy scripts
- Helper bash scripts
    - [import-pem-certs.sh](7.3.0/ig/bin/import-pem-certs.sh) used to import PEM certificates into the truststore

### import-pem-certs.sh

This script is used to import PEM certificates into the Java truststore.

This is required if IG needs to make TLS connections to resources that are not provided by commonly trusted Certificate
Authorities. For example, the Pre-Production Open Banking directory hosts its own Certificate Authority, which we need
to trust in order to make TLS calls to it.

The script can be configured using the following environment variables:

| Environment Variable  | Purpose                                                                                                                                                              | Default                                                                 |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| IG_PEM_TRUSTSTORE     | Path to a PEM file representing a truststore. The PEM can contain 1 or more X509 certificates, each of which will get added to the truststore created by this script | No default, if not supplied then the script exits with an error code -1 |
| TRUSTSTORE_PATH       | Path where the truststore created by this script is output                                                                                                           | /home/forgerock/igtruststore                                            |
| IG_DEFAULT_TRUSTSTORE | The default truststore which we want to extend. This truststore must already exist in the image. Typically, this will be the default JVM truststore                  | $JAVA_HOME/lib/security/cacerts                                         |
| TRUSTSTORE_PASSWORD   | Password for the IG_DEFAULT_TRUSTSTORE and for the new truststore that is output                                                                                     | changeit                                                                |
