del *.class
javac -classpath .;"%JAVA_HOME%\jre\lib\plugin.jar" *.java

del *.jar
jar -cvf DigitalSignerApplet.jar *.class

jarsigner -keystore DigitalSignerApplet.jks -storepass !secret -keypass !secret DigitalSignerApplet.jar signFiles

pause
