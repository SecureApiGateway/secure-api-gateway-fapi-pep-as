import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.KeyUse;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;




import java.io.FileInputStream;
import java.io.InputStream
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;


import java.util.Base64
import java.security.KeyStore

OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97"
QC_STATEMENTS_QWAC  = "MIHLMAgGBgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGAzAJBgcEAIvsSQECMIGeBgYEAIGYJwIwgZMwajApBgcEAIGYJwEEDB5DYXJkIEJhc2VkIFBheW1lbnQgSW5zdHJ1bWVudHMwHgYHBACBmCcBAwwTQWNjb3VudCBJbmZvcm1hdGlvbjAdBgcEAIGYJwECDBJQYXltZW50IEluaXRpYXRpb24MHUZvcmdlUm9jayBGaW5hbmNpYWwgQXV0aG9yaXR5DAZHQi1GRkE=";
QC_STATEMENTS_QSEAL = "MIHLMAgGBgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGAjAJBgcEAIvsSQECMIGeBgYEAIGYJwIwgZMwajApBgcEAIGYJwEEDB5DYXJkIEJhc2VkIFBheW1lbnQgSW5zdHJ1bWVudHMwHgYHBACBmCcBAwwTQWNjb3VudCBJbmZvcm1hdGlvbjAdBgcEAIGYJwECDBJQYXltZW50IEluaXRpYXRpb24MHUZvcmdlUm9jayBGaW5hbmNpYWwgQXV0aG9yaXR5DAZHQi1GRkE="
BC_PROVIDER = "BC";
KEY_ALGORITHM = "RSA";

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[JwkmsIssueCert] (" + fapiInteractionId + ") - ";

enum EidasCertType{
    SEAL, WAC
}



// Issue new transport certificate for API Client testing
//
// Certificate has its own private key embedded as a custom extension for use by test JWMKMS service
//
// Not for live clients!

logger.info(SCRIPT_NAME + "Running...")

def issueCert(certType,keySize,validityDays,subjectCN,subjectOI,caCertificate,caKey,providerName,keyAlg,sigAlg) {

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlg, providerName);
    keyPairGenerator.initialize(keySize);

    // Setup certificate start date to yesterday and end date from config

    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.DATE, -1);
    Date startDate = calendar.getTime();

    calendar.add(Calendar.DATE, validityDays);
    Date endDate = calendar.getTime();

    // Generate a new KeyPair and CSR

    X500Name issuedCertSubject = new X500Name("CN=" + subjectCN + ",OID." + OID_ORGANIZATIONAL_IDENTIFIER + "=" + subjectOI);
    // BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
    //  issuedCertSerialNum = new BigInteger(1, issuedCertSerialNum.toByteArray())
    BigInteger issuedCertSerialNum = new BigInteger(128,new Random());
    if (issuedCertSerialNum.signum() == -1) {
        logger.debug(SCRIPT_NAME + "Negating serial")
        issuedCertSerialNum = issuedCertSerialNum.negate();
    }

    logger.debug(SCRIPT_NAME + "Issuing with serial number " + issuedCertSerialNum);
    KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

    PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
    JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(sigAlg).setProvider(providerName);

    // Sign the CSR with the CA key

    ContentSigner csrContentSigner = csrBuilder.build(caKey);
    PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

    X500Name certIssuer = new X500Name(caCertificate.getSubjectDN().getName())
    X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(certIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

    JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

    // Add Extensions

    issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(caCertificate));
    issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
    issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
    issuedCertBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));


    // Currently build fixed qcstatements with all roles
    issuedCertBuilder.addExtension(Extension.qCStatements, false, Base64.getDecoder().decode(certType == EidasCertType.SEAL ? QC_STATEMENTS_QSEAL : QC_STATEMENTS_QWAC));

    X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
    X509Certificate issuedCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

    // Verify the issued cert signature against the CA cert
    issuedCert.verify(caCertificate.getPublicKey(), BC_PROVIDER);


    def JWKJsonResponse = null

    // build the JWK with private key representation and binding for the response to align the standard JSON Web Key
    // https://datatracker.ietf.org/doc/html/rfc7517#page-9

    def keyUse = (certType == EidasCertType.SEAL) ? "sig" : "tls";

    PublicKey publicKey = issuedCert.getPublicKey()

    if (publicKey instanceof RSAPublicKey) {
        RSAKey rsaJWK = RSAKey.parse(issuedCert)

        RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) issuedCertKeyPair.getPublic())
                .privateKey((RSAPrivateKey) issuedCertKeyPair.getPrivate());

        List<com.nimbusds.jose.util.Base64> x5c = new ArrayList<>(rsaJWK.getX509CertChain());
        def algo = rsaJWK.getAlgorithm()?null:new Algorithm("PS256")
        logger.debug(SCRIPT_NAME + "Algorithm of rskJWK is '" + algo + "'")
        JWKJsonResponse = builder
                .keyID(rsaJWK.getKeyID())
                .keyUse(KeyUse.parse(keyUse))
                .x509CertChain(x5c)
                .x509CertSHA256Thumbprint(rsaJWK.getX509CertSHA256Thumbprint())
                .x509CertURL(rsaJWK.getX509CertURL())
                .algorithm(algo)
                .build()
                .toJSONString();

    } else if (publicKey instanceof ECPublicKey) {
        ECKey ecJWK = ECKey.parse(issuedCert)

        ECKey.Builder builder = new ECKey.Builder((ECPublicKey) issuedCertKeyPair.getPublic())
                .privateKey((ECPrivateKey) issuedCertKeyPair.getPrivate());

        List<com.nimbusds.jose.util.Base64> x5c = new ArrayList<>(ecJWK.getX509CertChain());

        JWKJsonResponse = builder
                .keyID(ecJWK.getKeyID())
                .keyUse(KeyUse.parse(keyUse))
                .x509CertChain(x5c)
                .x509CertSHA256Thumbprint(ecJWK.getX509CertSHA256Thumbprint())
                .x509CertURL(ecJWK.getX509CertURL())
                .algorithm(ecJWK.getAlgorithm())
                .build()
                .toJSONString();
    } else {
        // unknown type, should never happen
    }

    return JWKJsonResponse;
}

// Read in request details

def requestObj = request.entity.getJson();

String subjectCN = requestObj.org_name;
String subjectOI = requestObj.org_id;

logger.debug(SCRIPT_NAME + "Issuing certificate for CN {} OI {}",subjectCN,subjectOI)

if (!(subjectCN && subjectOI)) {
    // response object
    response = new Response(Status.BAD_REQUEST)
    response.headers['Content-Type'] = "application/json"
    message = "Didn't get all input data"
    logger.error(SCRIPT_NAME + message)
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

// Load up the CA keystore



Security.addProvider(new BouncyCastleProvider());


KeyStore keystore = KeyStore.getInstance(routeArgKeystoreType);

InputStream keystoreInputStream = new FileInputStream(routeArgKeystoreFile)

keystore.load(keystoreInputStream, routeArgKeystorePass.toCharArray());
X509Certificate caCertificate = (X509Certificate) keystore.getCertificate(routeArgKeyAlias);
PrivateKey caKey = (PrivateKey) keystore.getKey(routeArgKeyAlias, routeArgKeyPass.toCharArray());
PublicKey caPublicKey = caCertificate.getPublicKey();

def sealJWK = issueCert(EidasCertType.SEAL,routeArgKeySize,routeArgValidityDays,subjectCN,subjectOI,caCertificate,caKey,BC_PROVIDER,KEY_ALGORITHM,routeArgSigningAlg);
def wacJWK = issueCert(EidasCertType.WAC,routeArgKeySize,routeArgValidityDays,subjectCN,subjectOI,caCertificate,caKey,BC_PROVIDER,KEY_ALGORITHM,routeArgSigningAlg);
Response response = new Response(Status.OK)
response.getHeaders().add("Content-Type","application/jwk+json");

def keySet = "{ \"keys\": [" + wacJWK + "," + sealJWK + "]}";

logger.debug(SCRIPT_NAME + "Final JSON " + keySet)
response.setEntity(keySet)

return response