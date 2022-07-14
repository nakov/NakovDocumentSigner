package demo;

import org.apache.struts.action.ActionForm;
import org.apache.struts.upload.FormFile;

/**
 * Struts action form class that maps to the form for uploading signed files
 * (SignedFileUploadForm-PFX.jsp or SignedFileUploadForm-SmartCard.jsp). It is
 * actually a data structure that consist of the uploaded file, the sender's
 * certification chain and the digital signature of the uploaded file.
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
public class SignedFileUploadActionForm extends ActionForm {

    private FormFile mUploadFile;
    private String mCertChain;
    private String mSignature;

    public FormFile getUploadFile() {
        return mUploadFile;
    }

    public void setUploadFile(FormFile aUploadFile) {
        mUploadFile = aUploadFile;
    }

    public String getCertChain() {
        return mCertChain;
    }

    public void setCertChain(String aCertChain) {
        mCertChain = aCertChain;
    }

    public String getSignature() {
        return mSignature;
    }

    public void setSignature(String aSignature) {
        mSignature = aSignature;
    }

}