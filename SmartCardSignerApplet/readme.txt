To generate self-signed certificate for signing the applet, run generate-certificate.bat.

To build the applet, run build-script.bat. Be sure to stop the Web browser (all its windows) and Java Plug-in before. Otherwise the file SmartCardSignerApplet.jar will be locked and will not be replaced (access denied).

You should use JDK 1.5 or later in order to compile and use this applet (PKCS#11 and smart cards support is available since Java 1.5).
