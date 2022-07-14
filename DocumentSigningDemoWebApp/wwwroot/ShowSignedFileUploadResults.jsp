<%
/**
 * A JSP for verifying digital signature, certificate and certification chain of the
 * received signed file. It assumes that the data, received by submitting some of the
 * forms SignedFileUploadForm-PFX.jsp or SignedFileUploadForm-SmartCard.jsp stays in
 * the user's session in SignedFileUploadActionForm object stored with the key
 * "signedFileUploadActionForm".
 *
 * The trusted certificates used for direct certificate verification should be located
 * in a directory whose name stays in the CERTS_FOR_DIRECT_VALIDATION_DIR constant
 * (see the code below).
 *
 * The trusted root CA certificates used for certification chain verification should be
 * located in a directory whose name stays in the TRUSTED_CA_ROOT_CERTS_DIR constant
 * (see the code below).
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
%>

<%@page import="demo.*,
                java.io.*,
                java.util.*,
                java.security.*,
                java.security.cert.*,
                org.apache.struts.upload.FormFile,
                javax.servlet.jsp.JspWriter" %>

<%!
    public static final String CERTS_FOR_DIRECT_VALIDATION_DIR =
        "/WEB-INF/certs-for-direct-validation";
    public static final String TRUSTED_CA_ROOT_CERTS_DIR =
		"/WEB-INF/trusted-CA-root-certs";

	private static final int KEY_USAGE_DIGITAL_SIGNATURE = 0;
	private static final int KEY_USAGE_NON_REPUDIATION = 1;
	private static final int KEY_USAGE_KEY_ENCIPHERMENT = 2;
	private static final int KEY_USAGE_DATA_ENCIPHERMENT = 3;
	private static final int KEY_USAGE_KEY_AGREEMENT = 4;
	private static final int KEY_USAGE_CERT_SIGN = 5;
	private static final int KEY_USAGE_CRL_SIGN = 6;
	private static final int KEY_USAGE_ENCIPHER_ONLY = 7;
	private static final int KEY_USAGE_DECIPHER_ONLY = 8;

    private ServletContext mApplicationContext = null;
    private JspWriter mOut = null;
    private SignedFileUploadActionForm mActionForm = null;
    private FormFile mReceivedFile = null;
    private byte[] mReceivedFileData = null;
    private CertPath mCertPath = null;
    private X509Certificate[] mCertChain = null;
    private X509Certificate mCertificate = null;
    private byte[] mSignature = null;
    private String mSignatureBase64Encoded;
%>

<html>
<body>
    <%
        mApplicationContext = application;
        mOut = out;
        mActionForm = (SignedFileUploadActionForm)
            session.getAttribute("signedFileUploadActionForm");

        if (mActionForm == null) {
            // User session does not contain the SignedFileUploadActionForm object
    %>
            Please choose file for signing first.
    <%
        } else {
            try {
                // Analyse received signed file and display information about it
                processReceivedFile();
                displayFileInfo(mReceivedFile, mReceivedFileData);
                mOut.println("<hr>");

                // Analyse received certification chain
                processReceivedCertificationChain();

                // Analyse received digital signature
                processReceivedSignature();

                // Display signature, verify it and display the verification results
                displaySignature(mSignatureBase64Encoded);
                verifyReceivedSignature();
                mOut.println("<hr>");

                // Display certificate, verify it and display the verification results
                displayCertificate(mCertificate);
                verifyReceivedCertificate();
                mOut.println("<hr>");

                // Display cert. chain, verify it and display the verification results
                displayCertificationChain(mCertChain);
                verifyReceivedCertificationChain();
            } catch (Exception e) {
                // Error occurred. Display the exception with its full stack trace
                out.println("<pre>Error: ");
                e.printStackTrace(new PrintWriter(out));
                out.println("</pre>");
            }
        }
    %>
    <br/>
    Go to the <a href="index.html">start page</a>.
</body>
</html>

<%!
    /**
     * Extracts the received file and its data from the received HTML form data. The
     * extracted file and its content are stored in the member variables mReceivedFile
     * and mReceivedFileData.
     * @throws Exception if no file is received.
     */
    private void processReceivedFile()
    throws Exception {
        mReceivedFile = mActionForm.getUploadFile();
        if (mReceivedFile == null) {
            throw new Exception("No file received. Please upload some file.");
        }
        mReceivedFileData = mReceivedFile.getFileData();
    }

    /**
     * Displays information about give file. Displays its file name and file size.
     */
    private void displayFileInfo(FormFile aFile, byte[] aFileData)
    throws Exception {
        String fileName = aFile.getFileName();
        mOut.println("Signed file successfully uploaded. <br>");
        mOut.println("File name: " + fileName + " <br>");
        mOut.println("File size: " + aFileData.length + " bytes. <br>");
    }

    /**
     * Analyses received certification chain and extracts the certificates that it
     * consist of. The certification chain should be PkiPath-encoded (ASN.1 DER
     * formatted), stored as Base64-string. The extracted chain is stored in the
     * member variables mCertPath as a CertPath object and in mCertChain as array
     * of X.509 certificates. Also the certificate used for signing the received
     * file is extracted in the member variable mCertificate.
     * @throws Exception if the received certification chain can not be decoded
     * (i.e. its encoding or internal format is invalid).
     */
    private void processReceivedCertificationChain()
    throws Exception {
        String certChainBase64Encoded = mActionForm.getCertChain();
        try {
            mCertPath = DigitalSignatureUtils.loadCertPathFromBase64String(
                certChainBase64Encoded);
            List certsInChain = mCertPath.getCertificates();
            mCertChain = (X509Certificate[])
                certsInChain.toArray(new X509Certificate[0]);
            mCertificate = mCertChain[0];
        }
        catch (Exception e) {
            throw new Exception("Invalid certification chain received.", e);
        }
    }

    /**
     * Displays given certification chain. Displays the length of the chain and the
     * subject distinguished names of all certificates in the chain, starting from
     * the first and finishing to the last.
     */
    private void displayCertificationChain(X509Certificate[] aCertChain)
    throws IOException {
        mOut.println("Certification chain length: " + aCertChain.length + " <br>");
        for (int i=0; i<aCertChain.length; i++) {
            Principal certPrincipal = aCertChain[i].getSubjectDN();
            mOut.println("certChain[" + i + "] = " + certPrincipal + " <br>");
        }
    }

    /**
     * Analyses received Base64-encoded digital signature, decodes it and stores it
     * in the member variable mSignature.
     * @throws Exception if the received signature can not be decoded.
     */
    private void processReceivedSignature()
    throws Exception {
        mSignatureBase64Encoded = mActionForm.getSignature();
        try {
            mSignature = Base64Utils.base64Decode(mSignatureBase64Encoded);
        } catch (Exception e) {
            throw new Exception("Invalid signature received.", e);
        }
    }

    /**
     * Displays given Base64-encoded digital signature.
     */
    private void displaySignature(String aSignatureBase64Encoded)
    throws IOException {
        mOut.println("Digital signature (Base64-encoded): " + aSignatureBase64Encoded);
    }

    /**
     * Verifies the received signature using the received file data and certificate
     * and displays the verification results. The received document, certificate and
     * signature are taken from the member variables mReceivedFileData, mCertificate
     * and mSignature respectively.
     */
    private void verifyReceivedSignature()
    throws IOException {
        mOut.println("Digital signature status: <b>");
        try {
            boolean signatureValid = DigitalSignatureUtils.verifyDocumentSignature(
                mReceivedFileData, mCertificate, mSignature);
            if (signatureValid)
                mOut.println("Signature is verified to be VALID.");
            else
                mOut.println("Signature is INVALID!");
        } catch (Exception e) {
            e.printStackTrace();
            mOut.println("Signature verification failed due to exception: " + e.toString());
        }
        mOut.println("</b>");
    }

    /**
     * Displays information about given certificate. This information includes the
     * certificate subject distinguished name and its purposes (public key usages).
     */
    private void displayCertificate(X509Certificate aCertificate)
    throws IOException {
        String certificateSubject = aCertificate.getSubjectDN().toString();
        mOut.println("Certificate subject: " + certificateSubject + " <br>");

		boolean[] certKeyUsage = aCertificate.getKeyUsage();
        mOut.println("Certificate purposes (public key usages): <br>");
		if (certKeyUsage != null) {
	        if (certKeyUsage[KEY_USAGE_DIGITAL_SIGNATURE])
				mOut.println("[digitalSignature] - verify digital signatures <br>");
	        if (certKeyUsage[KEY_USAGE_NON_REPUDIATION])
				mOut.println("[nonRepudiation] - verify non-repudiation <br>");
	        if (certKeyUsage[KEY_USAGE_KEY_ENCIPHERMENT])
				mOut.println("[keyEncipherment] - encipher keys for transport <br>");
	        if (certKeyUsage[KEY_USAGE_DATA_ENCIPHERMENT])
				mOut.println("[dataEncipherment] - encipher user data <br>");
	        if (certKeyUsage[KEY_USAGE_KEY_AGREEMENT])
				mOut.println("[keyAgreement] - use for key agreement <br>");
	        if (certKeyUsage[KEY_USAGE_CERT_SIGN])
				mOut.println("[keyCertSign] - verify signatures on certificates <br>");
	        if (certKeyUsage[KEY_USAGE_CRL_SIGN])
				mOut.println("[cRLSign] - verify signatures on CRLs <br>");
	        if (certKeyUsage[KEY_USAGE_ENCIPHER_ONLY])
				mOut.println("[encipherOnly] - encipher during key agreement <br>");
	        if (certKeyUsage[KEY_USAGE_DECIPHER_ONLY])
				mOut.println("[decipherOnly] - decipher during key agreement <br>");
		} else {
	        mOut.println("[No purposes defined] <br>");
		}
    }

    /**
     * Verifies received certificate directly and displays the verification results.
     * The certificate for verification is taken form mCertificate member variable.
     * Trusted certificates are taken from the CERTS_FOR_DIRECT_VALIDATION_DIR
     * directory. This directory should be relative to the Web application root
     * directory and should contain only .CER files (DER-encoded X.509 certificates).
     */
    private void verifyReceivedCertificate()
    throws IOException, GeneralSecurityException {
        // Create the list of the trusted certificates for direct validation
        X509Certificate[] trustedCertificates =
	        getCertificateList(mApplicationContext, CERTS_FOR_DIRECT_VALIDATION_DIR);

		// Verify the certificate and display the verification results
        mOut.println("Certificate direct verification status: <b>");
        try {
            DigitalSignatureUtils.verifyCertificate(mCertificate, trustedCertificates);
            mOut.println("Certificate is verified to be VALID.");
        } catch (CertificateExpiredException cee) {
            mOut.println("Certificate is INVALID (validity period expired)!");
        } catch (CertificateNotYetValidException cnyve) {
            mOut.println("Certificate is INVALID (validity period not yet started)!");
        } catch (DigitalSignatureUtils.CertificateValidationException cve) {
            mOut.println("Certificate is INVALID! " + cve.getMessage());
        }
        mOut.println("</b>");
    }

    /**
     * Verifies received certification chain and displays the verification results.
     * The chain for verification is taken form mCertPath member variable. Trusted CA
     * root certificates are taken from the TRUSTED_CA_ROOT_CERTS_DIR directory. This
     * directory should be relative to the Web application root directory and should
     * contain only .CER files (DER-encoded X.509 certificates).
     */
    private void verifyReceivedCertificationChain()
    throws IOException, GeneralSecurityException {
        // Create the most trusted CA set of trust anchors
        X509Certificate[] trustedCACerts =
            getCertificateList(mApplicationContext, TRUSTED_CA_ROOT_CERTS_DIR);

		// Verify the certification chain and display the verification results
        mOut.println("Certification chain verification: <b>");
        try {
			DigitalSignatureUtils.verifyCertificationChain(mCertPath, trustedCACerts);
            mOut.println("Certification chain verified to be VALID.");
        } catch (CertPathValidatorException cpve) {
            mOut.println("Certification chain is INVALID! Validation failed on cert " +
				"[" + cpve.getIndex() + "] from the chain: " + cpve.toString());
        }
        mOut.println("</b> <br>");
    }

   /**
    * @return a list of X509 certificates, obtained by reading all files from the
    * given directory. The supplied directory should be a given as a relative path
    * from the Web appication root (e.g. "/WEB-INF/test") and should contain only
    * .CER files (DER-encoded X.509 certificates).
    */
    private X509Certificate[] getCertificateList(ServletContext aServletContext,
        String aCertificatesDirectory)
    throws IOException, GeneralSecurityException {
        // Get a list of all files in the given directory
        Set trustedCertsResourceNames =
            aServletContext.getResourcePaths(aCertificatesDirectory);

        // Allocate an array for storing the certificates
        int count = trustedCertsResourceNames.size();
        X509Certificate[] trustedCertificates = new X509Certificate[count];

        // Read all X.509 certificate files one by one into an array
        int index = 0;
        Iterator trustedCertsResourceNamesIter = trustedCertsResourceNames.iterator();
        while (trustedCertsResourceNamesIter.hasNext()) {
            String certResName = (String) trustedCertsResourceNamesIter.next();
            InputStream certStream = aServletContext.getResourceAsStream(certResName);
            try {
                X509Certificate trustedCertificate =
                    DigitalSignatureUtils.loadX509CertificateFromStream(certStream);
                trustedCertificates[index] = trustedCertificate;
                index++;
            } finally {
                certStream.close();
            }
        }

        return trustedCertificates;
    }

%>