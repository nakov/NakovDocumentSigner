import java.applet.Applet;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import netscape.javascript.JSException;
import netscape.javascript.JSObject;

/**
 * Applet for digital signing documents. The applet is intended to be placed in a HTML
 * document containing a single HTML form that is used for applet input/output. The
 * applet accepts several parameters - the name of the field in the HTML form that
 * contains the file name to be signed and the names of the fields in the HTML form,
 * where the certification chain and signature should be stored.
 *
 * If the signing process is sucecssfull, the signature and certification chain fields
 * in the HTML form are filled. Otherwise an error message explaining the failure
 * reason is shown to the user.
 *
 * The applet asks the user to locate in his local file system a PFX file (PKCS#12
 * keystore), that holds his certificate (with the corresponding certification chain)
 * and its private key. Also the applet asks the user to enter his password for
 * accessing the keystore and the private key. If the specified file contains a
 * certificate and a corresponding private key that is accessible with supplied
 * password, the signature of the file is calculated and is placed in the HTML form.
 *
 * The applet considers taht the password for the keystore and the password for the
 * private key in it are the same (this is typical for the PFX files).
 *
 * In addition to the calculated signature the certification chain is extracted from
 * the PFX file and is placed in the HTML form too. The digital signature is stored as
 * Base64-encoded sequence of characters. The certification chain is stored as ASN.1
 * DER-encoded sequence of bytes, additionally encoded in Base64.
 *
 * In case the PFX file contains only one certificate without its full certification
 * chain, a chain consisting of this single certificate is extracted and stored in the
 * HTML form instead of the full certification chain.
 *
 * Digital singature algorithm used is SHA1withRSA. The length of the private key and
 * respectively the length of the calculated singature depend on the length of the
 * private key in the PFX file.
 *
 * The applet should be able to access the local machine's file system for reading and
 * writing. Reading the local file system is required for the applet to access the file
 * that should be signed and the PFX keystore file. Writing the local file system is
 * required for the applet to save its settings in the user's home directory.
 *
 * Accessing the local file system is not possible by default, but if the applet is
 * digitally signed (with jarsigner), it runs with no security restrictions. This
 * applet should be signed in order to run.
 *
 * A JRE version 1.4 or hihger is required for accessing the cryptography
 * functionality, so the applet will not run in any other Java runtime environment.
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
public class DigitalSignerApplet extends Applet {

    private static final String FILE_NAME_FIELD_PARAM = "fileNameField";
    private static final String CERT_CHAIN_FIELD_PARAM = "certificationChainField";
    private static final String SIGNATURE_FIELD_PARAM = "signatureField";
    private static final String SIGN_BUTTON_CAPTION_PARAM = "signButtonCaption";

    private static final String PKCS12_KEYSTORE_TYPE = "PKCS12";
    private static final String X509_CERTIFICATE_TYPE = "X.509";
    private static final String CERTIFICATION_CHAIN_ENCODING = "PkiPath";
    private static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";

    private Button mSignButton;

    /**
     * Initializes the applet - creates and initializes its graphical user interface.
     * Actually the applet consists of a single button, that fills its surface. The
     * button's caption comes from the applet parameter SIGN_BUTTON_CAPTION_PARAM.
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
     * the name of the file to be signed is obtained from FILE_NAME_FIELD_PARAM
     * applet parameter. The names of the output fields for the signature and the
     * certification chain are obtained from the parameters CERT_CHAIN_FIELD_PARAM
     * and SIGNATURE_FIELD_PARAM. The applet extracts the certificate, its chain
     * and its private key from a PFX file. The user is asked to select this PFX file
     * and the password for accessing it.
     */
    private void signSelectedFile() {
        try {
            // Get the file name to be signed from the form in the HTML document
            JSObject browserWindow = JSObject.getWindow(this);
            JSObject mainForm = (JSObject) browserWindow.eval("document.forms[0]");
            String fileNameFieldName = this.getParameter(FILE_NAME_FIELD_PARAM);
            JSObject fileNameField = (JSObject) mainForm.getMember(fileNameFieldName);
            String fileName = (String) fileNameField.getMember("value");

            // Perform file signing
            CertificationChainAndSignatureInBase64 signingResult = signFile(fileName);

            if (signingResult != null) {
                // Document signed. Fill the certificate and signature fields
                String certChainFieldName = this.getParameter(CERT_CHAIN_FIELD_PARAM);
                JSObject certChainField = (JSObject) mainForm.getMember(certChainFieldName);
                certChainField.setMember("value", signingResult.mCertChain);
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
                "Unable to access some of the fields in the\n" +
                "HTML form. Please check applet parameters.");
        }
        catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Unexpected error: " + e.getMessage());
        }
    }

    /**
     * Signs given local file. The certification chain and private key to be used for
     * signing are specified by the local user who choose a PFX file and password for
     * accessing it.
     * @param aFileName the name of the file to be signed.
     * @return the digital signature of the given file and the certification chain of
     * the certificate used for signing the file, both Base64-encoded or null if the
     * signing process is canceled by the user.
     * @throws DocumentSignException when a problem arise during the singing process
     * (e.g. invalid file format, invalid certificate, invalid password, etc.)
     */
    private CertificationChainAndSignatureInBase64 signFile(String aFileName)
    throws DocumentSignException {

        // Load the file for signing
        byte[] documentToSign = null;
        try {
            documentToSign = readFileInByteArray(aFileName);
        } catch (IOException ioex) {
            String errorMsg = "Can not read the file for signing " + aFileName + ".";
            throw new DocumentSignException(errorMsg, ioex);
        }

        // Show a dialog for selecting PFX file and password
        CertificateFileAndPasswordDialog certFileAndPasswdDlg =
            new CertificateFileAndPasswordDialog();
        if (certFileAndPasswdDlg.run()) {

            // Load the keystore from specified file using the specified password
            String keyStoreFileName = certFileAndPasswdDlg.getCertificateFileName();
            if (keyStoreFileName.length() == 0) {
                String errorMessage = "It is mandatory to select a certificate " +
                	"keystore (.PFX or .P12 file)!";
                throw new DocumentSignException(errorMessage);
            }
            String password = certFileAndPasswdDlg.getCertificatePassword();
            KeyStore userKeyStore = null;
            try {
                userKeyStore = loadKeyStoreFromPFXFile(keyStoreFileName, password);
            } catch (Exception ex) {
                String errorMessage = "Can not read certificate keystore file (" +
                    keyStoreFileName + ").\nThe file is either not in PKCS#12 format" +
                    " (.P12 or .PFX) or is corrupted or the password is invalid.";
                throw new DocumentSignException(errorMessage, ex);
            }

            // Get the private key and its certification chain from the keystore
            PrivateKeyAndCertChain privateKeyAndCertChain = null;
            try {
                privateKeyAndCertChain =
                    getPrivateKeyAndCertChain(userKeyStore, password);
            } catch (GeneralSecurityException gsex) {
                String errorMessage = "Can not extract certification chain and " +
                    "corresponding private key from the specified keystore file " +
                    "with given password. Probably the password is incorrect.";
                throw new DocumentSignException(errorMessage, gsex);
            }

            // Check if a private key is available in the keystore
            PrivateKey privateKey = privateKeyAndCertChain.mPrivateKey;
            if (privateKey == null) {
                String errorMessage = "Can not find the private key in the " +
                    "specified file " + keyStoreFileName + ".";
                throw new DocumentSignException(errorMessage);
            }

            // Check if X.509 certification chain is available
            Certificate[] certChain =
                privateKeyAndCertChain.mCertificationChain;
            if (certChain == null) {
                String errorMessage = "Can not find neither certificate nor " +
                    "certification chain in the file " + keyStoreFileName + ".";
                throw new DocumentSignException(errorMessage);
            }

            // Create the result object
            CertificationChainAndSignatureInBase64 signingResult =
                new CertificationChainAndSignatureInBase64();

            // Save X.509 certification chain in the result encoded in Base64
            try {
                signingResult.mCertChain = encodeX509CertChainToBase64(certChain);
            }
            catch (CertificateException cee) {
                String errorMessage = "Invalid certification chain found in the " +
                    "file " + keyStoreFileName + ".";
                throw new DocumentSignException(errorMessage);
            }

            // Calculate the digital signature of the file,
            // encode it in Base64 and save it in the result
            try {
                byte[] digitalSignature = signDocument(documentToSign, privateKey);
                signingResult.mSignature = Base64Utils.base64Encode(digitalSignature);
            } catch (GeneralSecurityException gsex) {
                String errorMessage = "Error signing file " + aFileName + ".";
                throw new DocumentSignException(errorMessage, gsex);
            }

            // Document signing completed succesfully
            return signingResult;
        }
        else {
            // Document signing canceled by the user
            return null;
        }
    }

    /**
     * Loads a keystore from .PFX or .P12 file (file format should be PKCS#12)
     * using given keystore password.
     */
    private KeyStore loadKeyStoreFromPFXFile(String aFileName, String aKeyStorePasswd)
    throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
        FileInputStream keyStoreStream = new FileInputStream(aFileName);
        char[] password = aKeyStorePasswd.toCharArray();
        keyStore.load(keyStoreStream, password);
        return keyStore;
    }

    /**
     * @return private key and certification chain corresponding to it, extracted from
     * given keystore using given password to access the keystore and the same password
     * to access the private key in it. The keystore is considered to have only one
     * entry that contains both certification chain and the corresponding private key.
     * If the certificate has no entries, an exception is trown. It the keystore has
     * several entries, the first is used.
     */
    private PrivateKeyAndCertChain getPrivateKeyAndCertChain(
        KeyStore aKeyStore, String aKeyPassword)
    throws GeneralSecurityException {
        char[] password = aKeyPassword.toCharArray();
        Enumeration aliasesEnum = aKeyStore.aliases();
        if (aliasesEnum.hasMoreElements()) {
            String alias = (String)aliasesEnum.nextElement();
            Certificate[] certificationChain = aKeyStore.getCertificateChain(alias);
            PrivateKey privateKey = (PrivateKey) aKeyStore.getKey(alias, password);
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
    static class CertificationChainAndSignatureInBase64 {
        public String mCertChain = null;
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
