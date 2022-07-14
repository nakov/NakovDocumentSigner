package demo;

import java.security.PublicKey;
import java.security.Signature;
import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.io.*;
import java.util.List;
import java.util.HashSet;

/**
 * Utility class for digital signatures and certificates verification.
 *
 * Verification of digital signature aims to confirm or deny that given signature is
 * created by signing given document with the private key corresponding to given
 * certificate. Verification of signatures is done with the standard digital signature
 * verification algorithm, provided by Java Cryptography API:
 *    1. The message digest is calculated from given document.
 *    2. The original message digest is obtained by decrypting the signature with the
 * public key of the signer (this public key is taken from the signer's certificate).
 *    3. Values calculated in step 1. and step 2. are compared.
 *
 * Verification of a certificate aims to check if the certificate is valid wihtout
 * inspecting its certification chain (sometimes it is unavailable). The certificate
 * verification is done in two steps:
 *    1. The certificate validity period is checked against current date.
 *    2. The certificate is checked if it is directly signed by some of the trusted
 * certificates that we have. A list of trusted certificates is supported for this
 * direct certificate verification process. If we want to successfully validate the
 * certificates issued by some certification authority (CA), we need to add the
 * certificate of this CA in our trusted list. Note that some CA have several
 * certificates and we should add only that of them, which the CA directly uses for
 * issuing certificates to its clients.
 *
 * Verification of a certification chains aims to check if given certificate is valid
 * by analysing its certification chain. A certification chain always starts with the
 * user certificate that should be verified, then several intermediate CA certificates
 * follow and at the end of the chain stays some root CA certificate. The verification
 * process includes following steps (according to PKIX algorithm):
 *    1. Check the certificate validity period against current date.
 *    2. Check if each certificate in the chain is signed by the previous.
 *    3. Check if all the certificates in the chain, except the first, belong to some
 * CA, i.e. if they are authorized to be used for signing other certificates.
 *    4. Check if the root CA certificate in the end of the chain is trusted, i.e. if
 * is it in the list of trusted root CA certificates.
 * The verification process uses PKIX algorithm, defined in RFC-3280, but don't use
 * CRL lists.
 *
 * This file is part of NakovDocumentSigner digital document
 * signing framework for Java-based Web applications:
 * http://www.nakov.com/documents-signing/
 *
 * Copyright (c) 2003 by Svetlin Nakov - http://www.nakov.com
 * National Academy for Software Development - http://academy.devbg.org
 * All rights reserved. This code is freeware. It can be used
 * for any purpose as long as this copyright statement is not
 * removed or modified.
 */
public class DigitalSignatureUtils {

    private static final String X509_CERTIFICATE_TYPE = "X.509";
    private static final String CERT_CHAIN_ENCODING = "PkiPath";
    private static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";
    private static final String CERT_CHAIN_VALIDATION_ALGORITHM = "PKIX";

    /**
     * Loads X.509 certificate from DER-encoded binary stream.
     */
    public static X509Certificate loadX509CertificateFromStream(InputStream aCertStream)
    throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        X509Certificate cert = (X509Certificate)cf.generateCertificate(aCertStream);
        return cert;
    }

    /**
     * Loads X.509 certificate from DER-encoded binary file (.CER file).
     */
    public static X509Certificate loadX509CertificateFromCERFile(String aFileName)
    throws GeneralSecurityException, IOException {
        FileInputStream fis = new FileInputStream(aFileName);
        X509Certificate cert = null;
        try {
            cert = loadX509CertificateFromStream(fis);
        } finally {
            fis.close();
        }
        return cert;
    }

    /**
     * Loads a certification chain from given Base64-encoded string, containing
     * ASN.1 DER formatted chain, stored with PkiPath encoding.
     */
    public static CertPath loadCertPathFromBase64String(String aCertChainBase64Encoded)
    throws CertificateException, IOException {
        byte[] certChainEncoded = Base64Utils.base64Decode(aCertChainBase64Encoded);
        CertificateFactory cf = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        InputStream certChainStream = new ByteArrayInputStream(certChainEncoded);
        CertPath certPath;
        try {
            certPath = cf.generateCertPath(certChainStream, CERT_CHAIN_ENCODING);
        } finally {
            certChainStream.close();
        }
        return certPath;
    }

    /**
     * Verifies given digital singature. Checks if given signature is obtained by
     * signing given document with the private key, corresponing to given public key.
     */
    public static boolean verifyDocumentSignature(byte[] aDocument,
        PublicKey aPublicKey, byte[] aSignature)
    throws GeneralSecurityException {
        Signature signatureAlgorithm =
            Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME);
        signatureAlgorithm.initVerify(aPublicKey);
        signatureAlgorithm.update(aDocument);
        boolean valid = signatureAlgorithm.verify(aSignature);
        return valid;
    }

    /**
     * Verifies given digital singature. Checks if given signature is obtained by
     * signing given document with the private key, corresponing to given certificate.
     */
    public static boolean verifyDocumentSignature(byte[] aDocument,
        X509Certificate aCertificate, byte[] aSignature)
    throws GeneralSecurityException {
        PublicKey publicKey = aCertificate.getPublicKey();
        boolean valid = verifyDocumentSignature(aDocument, publicKey, aSignature);
        return valid;
    }

    /**
     * Verifies a certificate. Checks its validity period and tries to find a trusted
     * certificate from given list of trusted certificates that is directly signed
     * given certificate. The certificate is valid if no exception is thrown.
     *
     * @param aCertificate the certificate to be verified.
     * @param aTrustedCertificates a list of trusted certificates to be used in
     * the verification process.
     *
     * @throws CertificateExpiredException if the certificate validity period is
     * expired.
     * @throws CertificateNotYetValidException if the certificate validity period is
     * not yet started.
     * @throws CertificateValidationException if the certificate is invalid (can not
     * be validated using the given set of trusted certificates.
     */
    public static void verifyCertificate(X509Certificate aCertificate,
        X509Certificate[] aTrustedCertificates)
    throws GeneralSecurityException {
        // First check certificate validity period
        aCertificate.checkValidity();

        // Check if the certificate is signed by some of the given trusted certificates
        for (int i=0; i<aTrustedCertificates.length; i++) {
            X509Certificate trustedCert = aTrustedCertificates[i];
            try {
                aCertificate.verify(trustedCert.getPublicKey());
                // Found parent certificate. Certificate is verified to be valid
                return;
            }
            catch (GeneralSecurityException ex) {
                // Certificate is not signed by current trustedCert. Try the next one
            }
        }

        // Certificate is not signed by any of the trusted certs --> it is invalid
        throw new CertificateValidationException(
            "Can not find trusted parent certificate.");
    }

    /**
     * Verifies certification chain using "PKIX" algorithm, defined in RFC-3280. It is
     * considered that the given certification chain start with the target certificate
     * and finish with some root CA certificate. The certification chain is valid if
     * no exception is thrown.
     *
     * @param aCertChain the certification chain to be verified.
     * @param aTrustedCACertificates a list of most trusted root CA certificates.
     * @throws CertPathValidatorException if the certification chain is invalid.
     */
    public static void verifyCertificationChain(CertPath aCertChain,
        X509Certificate[] aTrustedCACertificates)
    throws GeneralSecurityException {
        int chainLength = aCertChain.getCertificates().size();
        if (chainLength < 2) {
            throw new CertPathValidatorException("The certification chain is too " +
                "short. It should consist of at least 2 certiicates.");
        }

        // Create a set of trust anchors from given trusted root CA certificates
        HashSet trustAnchors = new HashSet();
        for (int i = 0; i < aTrustedCACertificates.length; i++) {
            TrustAnchor trustAnchor = new TrustAnchor(aTrustedCACertificates[i], null);
            trustAnchors.add(trustAnchor);
        }

        // Create a certification chain validator and a set of parameters for it
        PKIXParameters certPathValidatorParams = new PKIXParameters(trustAnchors);
        certPathValidatorParams.setRevocationEnabled(false);
        CertPathValidator chainValidator =
            CertPathValidator.getInstance(CERT_CHAIN_VALIDATION_ALGORITHM);

        // Remove the root CA certificate from the end of the chain. This is required
        // by the validation algorithm because by convention the trust anchor
        // certificates should not be a part of the chain that is validated
        CertPath certChainForValidation = removeLastCertFromCertChain(aCertChain);

        // Execute the certification chain validation
        chainValidator.validate(certChainForValidation, certPathValidatorParams);
    }

    /**
     * Removes the last certificate from given certification chain.
     * @return given cert chain without the last certificate in it.
     */
    private static CertPath removeLastCertFromCertChain(CertPath aCertChain)
    throws CertificateException {
        List certs = aCertChain.getCertificates();
        int certsCount = certs.size();
        List certsWithoutLast = certs.subList(0, certsCount-1);
        CertificateFactory cf = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        CertPath certChainWithoutLastCert = cf.generateCertPath(certsWithoutLast);
        return certChainWithoutLastCert;
    }

    /**
     * Exception class for certificate validation errors.
     */
    public static class CertificateValidationException
    extends GeneralSecurityException {
        public CertificateValidationException(String aMessage) {
            super(aMessage);
        }
    }

}
