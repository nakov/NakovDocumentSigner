package demo;

import javax.servlet.http.*;
import org.apache.struts.action.*;

/**
 * Struts action class for handling the results of submitting the forms
 * SignedFileUploadForm-PFX.jsp and SignedFileUploadForm-SmartCard.jsp.
 *
 * It gets the data from the form as SignedFileUploadActionForm object and puts this
 * object in the current user's session with key "signedFileUploadActionForm". After
 * that this action redirects the user's Web browser to ShowSignedFileUploadResults.jsp
 * that is used to display the received file, certificate, certification chain and
 * digital signature and their validity.
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
public class SignedFileUploadAction extends Action {

    public ActionForward perform(ActionMapping aActionMapping, ActionForm aActionForm,
            HttpServletRequest aRequest, HttpServletResponse aResponse) {
        SignedFileUploadActionForm signedFileUploadActionForm =
            (SignedFileUploadActionForm) aActionForm;
        HttpSession session = aRequest.getSession();
        session.setAttribute("signedFileUploadActionForm", signedFileUploadActionForm);

        return aActionMapping.findForward("ShowSignedFileUploadResults");
    }

}