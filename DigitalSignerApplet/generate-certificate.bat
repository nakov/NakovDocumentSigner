del DigitalSignerApplet.jks
keytool -genkey -alias signFiles -keystore DigitalSignerApplet.jks -keypass !secret -dname "CN=Your Company" -storepass !secret
pause