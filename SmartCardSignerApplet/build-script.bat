set JAVA5_HOME=C:\Progra~1\Java\jdk1.5.0_04

del *.class
%JAVA5_HOME%\bin\javac -classpath .;"%JAVA5_HOME%\jre\lib\plugin.jar" *.java

del *.jar
%JAVA5_HOME%\bin\jar -cvf SmartCardSignerApplet.jar *.class

%JAVA5_HOME%\bin\jarsigner -keystore SmartCardSignerApplet.jks -storepass !secret -keypass !secret SmartCardSignerApplet.jar signFiles

pause
