# NakovDocumentSigner: Java-Applet Based Digital Signature Framework

Obsolete technology for signing files and documents in the Web browser with a digital certificate + a private key, through a Java applet.

## What is NakovDocumentSigner?

**NakovDocumentSigner** is a framework for digitally signing document for Java-based Web applications, build in September 2005. It is freeware open-source project initiated by Svetlin Nakov and provides the Web applications with digital signature functionality based on Public Key Infrastructure (PKI). NakovDocumentSigner consists of a digital signer applet and a reference Web application for signature and certificate verification. It supports signing with a PKCS#12 certificate keystore file (PFX / P12 file) and with a smart card (PKCS #11).

The **DigitalSignerApplet** is a Java applet that signs files on the client’s machine before uploading to the Web server. It is intended to be integrated in HTML forms for file uploading and provides digital signature functionality based on public key cryptography and X.509 certificates. The applet allows the user to locate his certificate PKCS#12 keystore file (.PFX or .P12 file) and to enter his password for accessing it. After that it signs the file that is selected for uploading with the private key from the selected keystore and puts the calculated signature along with the full certificate chain from the keystore in the HTML form. When the form is submitted, the calculated signature and user’s full certificate chain is transmitted to the server along with the selected file for uploading. The applet is digitally signed in order to run with full permissions on the client machine and requires Java Plug-In 1.4 or later on the client.

The **SmartCardSignerApplet** works the same way like the DigitalSignerApplet but it signs files in the client’s Web browser with a smart card. It needs a PKCS#11 implementation library (.dll or .so file) and the PIN code for accessing the smart card. The applets requires Java Plug-In 1.5 or later.

The **sample Web application** is intended to illustrate how digital document signing process, powered by the digital signer applet, can be integrated in Java-based Web applications. The sample application is based on Struts framework and shows how signed files can be received and how their digital signatures can be verifed on the server. In addition to this, the sample application shows how the user certificates and certificate chains can be verified. User certificates are verified in two ways – directly and by verifying their certificate chains. In practice this sample application can be used as framework for integration of the Public Key Infrastructure (PKI) and digital document signing in Web application.

## Obsolete Technology

Warning: the Java applets technology is obsolete and is no longer supported in modern Web browsers.

The most stable solution for signing documents with a smart card in the Web browser (as of June 2016) is the hwcrypto.js from ID.ee (the Estonian government crypto project). Is provides JavaScript crypto API and browser plugins for Chrome, Firefox and Internet Explorer to access smart cards and sign documents in the browser.

In some browsers **WebCrypto API** is supported. See some examples here: https://github.com/diafygi/webcrypto-examples.

## Project Architecture

![image](https://user-images.githubusercontent.com/1689586/186133378-235fbe90-97ea-43a7-ac91-31e8b5817d41.png)

## Screenshots

TODO

## Live Demos
 - Demonstration of digitally signing files in your Web browser with PFX certificate keystore (DigitalSignerApplet): https://nakov.com/research/documents-signing/digitalsignerapplet-demo
 - Demonstration of digitally signing files in your Web browser with a smart card (SmartCardSignerApplet): https://nakov.com/research/documents-signing/smartcardsignerapplet-demo

## More Info

https://nakov.com/research/documents-signing

