/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.util;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Pair;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.RSAKey.Builder;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Collection of util methods to aid in the generation of crypto related objects such as: KeyPair, X509Certificate,
 * JWK and JWKSet objects
 */
public class CryptoUtils {

    private static final RSASSASigner ssaSigner;

    static {
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        ssaSigner =  new RSASSASigner(pair.getPrivate());
    }

    /**
     * Generate a random RSA KeyPair
     */
    public static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate a self-signed X509 cert for a KeyPair
     */
    public static X509Certificate generateX509Cert(KeyPair keyPair, String subjectDN) {
        return generateX509Cert(keyPair, subjectDN, null, null);
    }

    public static X509Certificate generateX509Cert(KeyPair keyPair, String subjectDN, Date startDate, Date endDate) {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        long now = System.currentTimeMillis();
        if (startDate == null) {
            startDate = new Date(now);
        }
        if (endDate == null) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(startDate);
            calendar.add(Calendar.YEAR, 1);
            endDate = calendar.getTime();
        }

        X500Name dnName = new X500Name(subjectDN);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));
        String signatureAlgorithm;
        final String algorithm = keyPair.getPublic().getAlgorithm();
        if (algorithm.equals("RSA")) {
            signatureAlgorithm = "SHA256WithRSA";
        } else {
            throw new IllegalStateException("keyPair algorithm not supported: " + algorithm + " please updated test code to handle this");
        }
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());
            BasicConstraints basicConstraints = new BasicConstraints(true);
            certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);
            return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
        } catch (CertificateException | CertIOException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate generateExpiredX509Cert(KeyPair keyPair, String subjectDN) {
        final Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_YEAR, -5);
        final Date certStartDate = calendar.getTime();
        calendar.add(Calendar.DAY_OF_YEAR, 1);
        final Date certEndDate = calendar.getTime();

        return generateX509Cert(keyPair, subjectDN, certStartDate, certEndDate);
    }

    /**
     * Convert an X509Certificate to a PEM string representation
     */
    public static String convertToPem(X509Certificate cert) {
        final StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            PemObjectGenerator gen = new JcaMiscPEMGenerator(cert);
            pw.writeObject(gen);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return sw.toString();
    }

    /**
     * Helper method to generate a Test Transport Cert and a JWKSet which contains this certificate and several other
     * generated certs
     */
    public static Pair<X509Certificate, JWKSet> generateTestTransportCertAndJwks(String transportCertKeyUse) throws Exception {
        final KeyPair keyPair = generateRsaKeyPair();
        final X509Certificate testTransportCert = generateX509Cert(keyPair, "CN=testCert");

        final KeyUse keyUse = new KeyUse(transportCertKeyUse);
        final List<JWK> keys = new ArrayList<>();
        // Add testTransportCert to the JWKS
        JWK matchingJwk = createJwkForCert(testTransportCert, keyUse);
        keys.add(matchingJwk);

        // Generate several others certs to add to the JWKS
        for (int i = 0 ; i < 5; i++) {
            final KeyUse randomKeyUse = i % 2 == 0 ? keyUse : new KeyUse("sig");
            keys.add(createJwkForCert(generateX509Cert(generateRsaKeyPair(), "CN=blah" + i), randomKeyUse));
        }
        // Randomise the key order
        Collections.shuffle(keys);

        final JWKSet jwkSet = JWKSet.parse(new com.nimbusds.jose.jwk.JWKSet(keys).toString());
        return Pair.of(testTransportCert, jwkSet);
    }

    public static RSAKey createJwkForCert(X509Certificate x509Certificate, KeyUse keyUse) throws JOSEException {
        final Builder jwkBuilder = new Builder(RSAKey.parse(x509Certificate));
        jwkBuilder.keyUse(keyUse);
        final RSAKey jwk = jwkBuilder.build();
        return jwk;
    }

    /**
     * Uses nimbusds to create a SignedJWT and returns JWS object in its compact format consisting of
     * Base64URL-encoded parts delimited by period ('.') characters.
     *
     * @param claims      The claims to include in the signed jwt
     * @param signingAlgo the algorithm to use for signing
     * @return the jws in its compact form consisting of Base64URL-encoded parts delimited by period ('.') characters.
     */
    public static String createEncodedJwtString(Map<String, Object> claims, JWSAlgorithm signingAlgo) {
        try {
            JWSHeader.Builder builder = new JWSHeader.Builder(signingAlgo);
            builder.keyID(UUID.randomUUID().toString());
            JWSHeader jwsHeader = builder.build();

            final SignedJWT signedJWT = new SignedJWT(jwsHeader, JWTClaimsSet.parse(claims));
            signedJWT.sign(ssaSigner);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a {@link Request} with the given certificate
     *
     * @param certificate
     *         the certificate to use for the request
     * @return the {@link Request}
     */
    public static Request createRequestWithCertHeader(X509Certificate certificate) {
        return createRequestWithCertHeader(certificate, "clientCertHeader");
    }

    /**
     * Create a {@link Request} with the given certificate
     * @param certificate
     *      the certificate to use for the request
     * @param headerName
     *       the header to put the certificate
     * @return the {@link Request}
     */
    public static Request createRequestWithCertHeader(X509Certificate certificate, final String headerName) {
        Request request = new Request();
        String certUrlEncodedPem = URLEncoder.encode(convertToPem(certificate), StandardCharsets.UTF_8);
        request.addHeaders(new GenericHeader(headerName, certUrlEncodedPem));
        return request;
    }
}
