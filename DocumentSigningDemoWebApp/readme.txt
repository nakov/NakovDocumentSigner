To compile the reference Web-application use the build script "build.xml"
and the tool Apache Ant.

To build the application use these sommands:

cd %NakovDocumentSignerHome%
cd %DocumentSigningDemoWebApp%
%ANT_HOME%\bin\ant.bat

You should have %JAVA_HOME% environment variable to point your JDK 1.4
or later installation.

The result of the compilation is the file "DocumentSigningDemoWebApp.war" in
the "deploy" subdirectory.

The DocumentSigningDemoWebApp.war is J2EE-compliant Web-application and
can be executed in a standart J2EE Servlet/JSP container or application server.
