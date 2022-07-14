del SmartCardSignerApplet.jks
keytool -genkey -alias signFiles -keystore SmartCardSignerApplet.jks -keypass !secret -dname "CN=Your Company" -storepass !secret
pause