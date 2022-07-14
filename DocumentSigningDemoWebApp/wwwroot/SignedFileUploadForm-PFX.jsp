<%
/**
 * A JSP that contains the form for signing and uploading a file. The form
 * contains 3 fields - the file to be uploaded, the certification chain and
 * the digital signature. It also contains the DigitalSignerApplet that signs
 * the selected file on the client's machine.
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

<%@ taglib uri="/WEB-INF/taglibs/struts-html.tld" prefix="html" %>

<html>
<body>

<html:form type="demo.SignedFileUploadActionForm" action="/SignedFileUpload"
        method="post" enctype="multipart/form-data">
    Please choose file to sign and upload: <html:file property="uploadFile"/> <br>
    Certification chain (Base64-encoded): <html:text property="certChain"/> <br>
    Digital signature (Base64-encoded): <html:text property="signature"/> <br>

    <br>

    <object
        classid="clsid:8AD9C840-044E-11D1-B3E9-00805F499D93"
        codebase="http://java.sun.com/products/plugin/autodl/jinstall-1_4-windows-i586.cab#Version=1,4,0,0"
        width="130" height="25" name="DigitalSignerApplet">
        <param name="type" value="application/x-java-applet;version=1.4">
        <param name="code" value="DigitalSignerApplet">
        <param name="archive" value="DigitalSignerApplet.jar">
        <param name="mayscript" value="true">
        <param name="scriptable" value="true">
        <param name="fileNameField" value="uploadFile">
        <param name="certificationChainField" value="certChain">
        <param name="signatureField" value="signature">
        <param name="signButtonCaption" value="Sign selected file">

        <comment>
            <embed
                type="application/x-java-applet;version=1.4"
                pluginspage="http://java.sun.com/products/plugin/index.html#download"
                code="DigitalSignerApplet"
                archive="DigitalSignerApplet.jar"
                width="130"
                height="25"
                mayscript="true"
                scriptable="true"
                fileNameField="uploadFile"
                certificationChainField="certChain"
                signatureField="signature"
                signButtonCaption="Sign selected file">
            <noembed>
                Document signing applet can not be started because 
                Java Plug-In version 1.4 or later is not installed.
            </noembed>
        </embed>
        </comment>
    </object>

    <br>
    <br>

    <html:submit property="submit" value="Upload file"/>
</html:form>

</body>
</html>
