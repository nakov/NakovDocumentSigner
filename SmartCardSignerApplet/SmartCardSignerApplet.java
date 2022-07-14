import java.applet.Applet;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.lang.reflect.Constructor;

import netscape.javascript.JSException;
import netscape.javascript.JSObject;

/**
 * Applet for digital signing documents with a smart card. The applet is intended to
 * be placed in a HTML document containing a single HTML form that is used for applet
 * input/output. The applet accepts several parameters - the name of the field in the
 * HTML form that contains the file name to be signed and the names of the fields in
 * the HTML form, where the certification chain and signature should be stored.
 *
 * If the signing process is sucecssfull, the signature and certification chain fields
 * in the HTML form are filled. Otherwise an error message explaining the failure
 * reason is shown.
 *
 * The applet asks the user to locate in his local file system the PKCS#11
 * implementation library that is part of software that come with the smart card
 * and the smart card reader. Usually this is a Windows .DLL file located in Windows
 * system32 directory or .so library (e.g. C:\windows\system32\pkcs201n.dll).
 *
 * The applet also asks the user to enter his PIN code for accessing the smart card.
 * If the smart card contains a certificate and a corresponding private key, the
 * signature of the file is calculated and is placed in the HTML form. In addition
 * to the calculated signature the certificate with its full certification chain is
 * extracted from the smart card and is placed in the HTML form too. The digital
 * signature is placed as Base64-encoded sequence of bytes. The certification chain
 * is placed as ASN.1 DER-encoded sequence of bytes, additionally encoded in Base64.
 * In case the smart card contains only one certificate without its full certification
 * chain, a chain consisting of this single certificate is extracted and stored in the
 * HTML form instead of a full certification chain.
 *
 * Digital singature algorithm used is SHA1withRSA. The length of the calculated
 * singature depends on the length of the private key on the smart card.
 *
 * The applet should be able to access the local machine's file system for reading and
 * writing. Reading the local file system is required for the applet to access the file
 * that should be signed. Writing the local file system is required for the applet to
 * save its settings in the user's home directory. Accessing the local file system is
 * not possible by default, but if the applet is digitally signed (with jarsigner), it
 * runs with no security restrictions and can do anything. This applet should be signed
 * in order to run.
 *
 * Java Plug-In version 1.5 or hihger is required for accessing the PKCS#11 smart card
 * functionality, so the applet will not run in any other Java runtime environment.
 *
 * This file is part of NakovDocumentSigner digital document
 * signing framework for Java-based Web applications:
 * http://www.nakov.com/documents-signing/
 *
 * Copyright (c) 2005 by Svetlin Nakov - http://www.nakov.com
 * All rights reserved. This code is freeware. It can be used
 * for any purpose as long as this copyright statement is not
 * removed or modified.
 */
public class SmartCardSignerApplet extends Applet {

    private static final String FILE_NAME_FIELD_PARAM = "fileNameField";
    private static final String CERT_CHAIN_FIELD_PARAM = "certificationChainField";
    private static final String SIGNATURE_FIELD_PARAM = "signatureField";
    private static final String SIGN_BUTTON_CAPTION_PARAM = "signButtonCaption";

    private static final String PKCS11_KEYSTORE_TYPE = "PKCS11";
    private static final String X509_CERTIFICATE_TYPE = "X.509";
    private static final String CERTIFICATION_CHAIN_ENCODING = "PkiPath";
    private static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";
    private static final String SUN_PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";

    private Button mSignButton;

    /**
     * Initializes the applet - creates and initializes its graphical user interface.
     * Actually the applet consists of a single button, that fills its all surface. The
     * button's caption is taken from the applet parameter SIGN_BUTTON_CAPTION_PARAM.
     */
    public void init() {
        String signButtonCaption = this.getParameter(SIGN_BUTTON_CAPTION_PARAM);
        mSignButton = new Button(signButtonCaption);
        mSignButton.setLocation(0, 0);
        Dimension appletSize = this.getSize();
        mSignButton.setSize(appletSize);
        mSignButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e) {
                signSelectedFile();
            }
        });
        this.setLayout(null);
        this.add(mSignButton);
    }

    /**
     * Signs the selected file. The file name comes from a field in the HTML document.
     * The result consists of the calculated digital signature and certification chain,
     * both placed in fields in the HTML document, encoded in Base64 format. The HTML
     * document should contain only one HTML form. The name of the field, that contains
     * the name of the file to be signed is obtained from FILE_NAME_FIELD_PARAM applet
     * parameter. The names of the output fields for the signature and the
     * certification chain are obtained from the parameters CERT_CHAIN_FIELD_PARAM
     * and SIGNATURE_FIELD_PARAM. The user is asket to choose a PKCS#11 implementation
     * library and a PIN code for accessing the smart card.
     */
    private void signSelectedFile() {
        try {
            // Get the file name to be signed from the form in the HTML document
            JSObject browserWindow = JSObject.getWindow(this);
            JSObject mainForm = (JSObject) browserWindow.eval("document.forms[0]");
            String fileNameFieldName = this.getParameter(FILE_NAME_FIELD_PARAM);
            JSObject fileNameField = (JSObject) mainForm.getMember(fileNameFieldName);
            String fileName = (String) fileNameField.getMember("value");

            // Perform the actual file signing
            CertificationChainAndSignatureBase64 signingResult = signFile(fileName);
            if (signingResult != null) {
                // Document  signed. Fill the certificate and signature fields
                String certChainFieldName = this.getParameter(CERT_CHAIN_FIELD_PARAM);
                JSObject certChainField = (JSObject) mainForm.getMember(certChainFieldName);
                certChainField.setMember("value", signingResult.mCertificationChain);
                String signatureFieldName = this.getParameter(SIGNATURE_FIELD_PARAM);
                JSObject signatureField = (JSObject) mainForm.getMember(signatureFieldName);
                signatureField.setMember("value", signingResult.mSignature);
            } else {
                // User canceled signing
            }
        }
        catch (DocumentSignException dse) {
            // Document signing failed. Display error message
            String errorMessage = dse.getMessage();
            JOptionPane.showMessageDialog(this, errorMessage);
        }
        catch (SecurityException se) {
            se.printStackTrace();
            JOptionPane.showMessageDialog(this,
                "Unable to access the local file system.\n" +
                "This applet should be started with full security permissions.\n" +
                "Please accept to trust this applet when the Java Plug-In ask you.");
        }
        catch (JSException jse) {
            jse.printStackTrace();
            JOptionPane.showMessageDialog(this,
                "Unable to access some of the fields of the\n" +
                "HTML form. Please check the applet parameters.");
        }
        catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Unexpected error: " + e.getMessage());
        }
    }

    /**
     * Signs given local file. The certificate and private key to be used for signing
     * come from the locally attached smart card. The user is requested to provide a
     * PKCS#11 implementation library and the PIN code for accessing the smart card.
     * @param aFileName the name of the file to be signed.
     * @return the digital signature of the given file and the certification chain of
     * the certificatie used for signing the file, both Base64-encoded or null if the
     * signing process is canceled by the user.
     * @throws DocumentSignException when a problem arised during the singing process
     * (e.g. smart card access problem, invalid certificate, invalid PIN code, etc.)
     */
    private CertificationChainAndSignatureBase64 signFile(String aFileName)
    throws DocumentSignException {

        // Load the file for signing
        byte[] documentToSign = null;
        try {
            documentToSign = readFileInByteArray(aFileName);
        } catch (IOException ioex) {
            String errorMessage = "Can not read the file for signing " + aFileName + ".";
            throw new DocumentSignException(errorMessage, ioex);
        }

        // Show a dialog for choosing PKCS#11 implementation library and smart card PIN
        PKCS11LibraryFileAndPINCodeDialog pkcs11Dialog =
            new PKCS11LibraryFileAndPINCodeDialog();
        boolean dialogConfirmed;
        try {
            dialogConfirmed = pkcs11Dialog.run();
        } finally {
            pkcs11Dialog.dispose();
        }

        if (dialogConfirmed) {
            String oldButtonLabel = mSignButton.getLabel();
            mSignButton.setLabel("Working...");
            mSignButton.setEnabled(false);
            try {
                String pkcs11LibraryFileName = pkcs11Dialog.getLibraryFileName();
                String pinCode = pkcs11Dialog.getSmartCardPINCode();

                // Do the actual signing of the document with the smart card
                CertificationChainAndSignatureBase64 signingResult =
                    signDocument(documentToSign, pkcs11LibraryFileName, pinCode);
                return signingResult;
            } finally {
                mSignButton.setLabel(oldButtonLabel);
                mSignButton.setEnabled(true);
            }
        }
        else {
            return null;
        }
    }

    private CertificationChainAndSignatureBase64 signDocument(
        byte[] aDocumentToSign, String aPkcs11LibraryFileName, String aPinCode)
    throws DocumentSignException {
        if (aPkcs11LibraryFileName.length() == 0) {
            String errorMessage = "It is mandatory to choose a PCKS#11 native " +
                "implementation library for for smart card (.dll or .so file)!";
            throw new DocumentSignException(errorMessage);
        }

        // Load the keystore from the smart card using the specified PIN code
        KeyStore userKeyStore = null;
        try {
            userKeyStore = loadKeyStoreFromSmartCard(aPkcs11LibraryFileName, aPinCode);
        } catch (Exception ex) {
            String errorMessage = "Can not read the keystore from the smart card.\n" +
                "Possible reasons:\n" +
                " - The smart card reader in not connected.\n" +
                " - The smart card is not inserted.\n" +
                " - The PKCS#11 implementation library is invalid.\n" +
                " - The PIN for the smart card is incorrect.\n" +
                "Problem details: " + ex.getMessage();
            throw new DocumentSignException(errorMessage, ex);
        }

        // Get the private key and its certification chain from the keystore
        PrivateKeyAndCertChain privateKeyAndCertChain = null;
        try {
            privateKeyAndCertChain =
                getPrivateKeyAndCertChain(userKeyStore);
        } catch (GeneralSecurityException gsex) {
            String errorMessage = "Can not extract the private key and " +
                "certificate from the smart card. Reason: " + gsex.getMessage();
            throw new DocumentSignException(errorMessage, gsex);
        }

        // Check if the private key is available
        PrivateKey privateKey = privateKeyAndCertChain.mPrivateKey;
        if (privateKey == null) {
            String errorMessage = "Can not find the private key on the smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Check if X.509 certification chain is available
        Certificate[] certChain = privateKeyAndCertChain.mCertificationChain;
        if (certChain == null) {
            String errorMessage = "Can not find the certificate on the smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Create the result object
        CertificationChainAndSignatureBase64 signingResult =
            new CertificationChainAndSignatureBase64();

        // Save X.509 certification chain in the result encoded in Base64
        try {
            signingResult.mCertificationChain = encodeX509CertChainToBase64(certChain);
        }
        catch (CertificateException cee) {
            String errorMessage = "Invalid certificate on the smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Calculate the digital signature of the file,
        // encode it in Base64 and save it in the result
        try {
            byte[] digitalSignature = signDocument(aDocumentToSign, privateKey);
            signingResult.mSignature = Base64Utils.base64Encode(digitalSignature);
        } catch (GeneralSecurityException gsex) {
            String errorMessage = "File signing failed.\n" +
                "Problem details: " + gsex.getMessage();
            throw new DocumentSignException(errorMessage, gsex);
        }

        return signingResult;
    }

    /**
     * Loads the keystore from the smart card using its PKCS#11 implementation
     * library and the Sun PKCS#11 security provider. The PIN code for accessing
     * the smart card is required.
     */
    private KeyStore loadKeyStoreFromSmartCard(String aPKCS11LibraryFileName,
        String aSmartCardPIN)
    throws GeneralSecurityException, IOException {
        // First configure the Sun PKCS#11 provider. It requires a stream (or file)
        // containing the configuration parameters - "name" and "library".
        String pkcs11ConfigSettings =
            "name = SmartCard\n" + "library = " + aPKCS11LibraryFileName;
        byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
        ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

        // Instantiate the provider dynamically with Java reflection
        try {
            Class sunPkcs11Class = Class.forName(SUN_PKCS11_PROVIDER_CLASS);
            Constructor pkcs11Constr = sunPkcs11Class.getConstructor(
                java.io.InputStream.class);
            Provider pkcs11Provider = (Provider) pkcs11Constr.newInstance(confStream);
            Security.addProvider(pkcs11Provider);
        } catch (Exception e) {
            throw new KeyStoreException("Can initialize Sun PKCS#11 security " +
                "provider. Reason: " + e.getCause().getMessage());
        }

        // Read the keystore form the smart card
        char[] pin = aSmartCardPIN.toCharArray();
        KeyStore keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE);
        keyStore.load(null, pin);
        return keyStore;
    }

    /**
     * @return private key and certification chain corresponding to it, extracted from
     * given keystore. The keystore is considered to have only one entry that contains
     * both certification chain and its corresponding private key. If the keystore has
     * no entries, an exception is thrown.
     */
    private PrivateKeyAndCertChain getPrivateKeyAndCertChain(
        KeyStore aKeyStore)
    throws GeneralSecurityException {
        Enumeration aliasesEnum = aKeyStore.aliases();
        if (aliasesEnum.hasMoreElements()) {
            String alias = (String)aliasesEnum.nextElement();
            Certificate[] certificationChain = aKeyStore.getCertificateChain(alias);
            PrivateKey privateKey = (PrivateKey) aKeyStore.getKey(alias, null);
            PrivateKeyAndCertChain result = new PrivateKeyAndCertChain();
            result.mPrivateKey = privateKey;
            result.mCertificationChain = certificationChain;
            return result;
        } else {
            throw new KeyStoreException("The keystore is empty!");
        }
    }

    /**
     * @return Base64-encoded ASN.1 DER representation of given X.509 certification
     * chain.
     */
    private String encodeX509CertChainToBase64(Certificate[] aCertificationChain)
    throws CertificateException {
        List certList = Arrays.asList(aCertificationChain);
        CertificateFactory certFactory =
            CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        CertPath certPath = certFactory.generateCertPath(certList);
        byte[] certPathEncoded = certPath.getEncoded(CERTIFICATION_CHAIN_ENCODING);
        String base64encodedCertChain = Base64Utils.base64Encode(certPathEncoded);
        return base64encodedCertChain;
    }

    /**
     * Reads the specified file into a byte array.
     */
    private byte[] readFileInByteArray(String aFileName)
    throws IOException {
        File file = new File(aFileName);
        FileInputStream fileStream = new FileInputStream(file);
        try {
            int fileSize = (int) file.length();
            byte[] data = new byte[fileSize];
            int bytesRead = 0;
            while (bytesRead < fileSize) {
                bytesRead += fileStream.read(data, bytesRead, fileSize-bytesRead);
            }
            return data;
        }
        finally {
            fileStream.close();
        }
    }

    /**
     * Signs given document with a given private key.
     */
    private byte[] signDocument(byte[] aDocument, PrivateKey aPrivateKey)
    throws GeneralSecurityException {
        Signature signatureAlgorithm =
            Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME);
        signatureAlgorithm.initSign(aPrivateKey);
        signatureAlgorithm.update(aDocument);
        byte[] digitalSignature = signatureAlgorithm.sign();
        return digitalSignature;
    }

    /**
     * Data structure that holds a pair of private key and
     * certification chain corresponding to this private key.
     */
    static class PrivateKeyAndCertChain {
        public PrivateKey mPrivateKey;
        public Certificate[] mCertificationChain;
    }

    /**
     * Data structure that holds a pair of Base64-encoded
     * certification chain and digital signature.
     */
    static class CertificationChainAndSignatureBase64 {
        public String mCertificationChain = null;
        public String mSignature = null;
    }

    /**
     * Exception class used for document signing errors.
     */
    static class DocumentSignException extends Exception {
        public DocumentSignException(String aMessage) {
            super(aMessage);
        }

        public DocumentSignException(String aMessage, Throwable aCause) {
            super(aMessage, aCause);
        }
    }

}