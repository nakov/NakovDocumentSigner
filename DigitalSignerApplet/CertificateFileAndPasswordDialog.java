import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import java.io.*;
import java.util.Properties;

/**
 * Dialog for choosing certificate file name and password for it. Allows the user to
 * choose a PFX file and enter a password for accessing it. The last used PFX file is
 * remembered in the config file called ".digital_signer_applet.config", located in
 * the user's home directory in order to be automatically shown the next time when
 * the same user access this dialog.
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
public class CertificateFileAndPasswordDialog extends JDialog {

    private static final String CONFIG_FILE_NAME = ".digital_signer_applet.config";
    private static final String PFX_FILE_NAME_KEY = "last-PFX-file-name";

    private JButton mBrowseForCertButton = new JButton();
    private JTextField mCertFileNameTextField = new JTextField();
    private JLabel mChooseCertFileLabel = new JLabel();
    private JTextField mPasswordTextField = new JPasswordField();
    private JLabel mEnterPasswordLabel = new JLabel();
    private JButton mSignButton = new JButton();
    private JButton mCancelButton = new JButton();

    private boolean mResult = false;

    /**
     * Initializes the dialog - creates and initializes its GUI controls.
     */
    public CertificateFileAndPasswordDialog() {
        // Initialize the dialog
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(426, 165));
        this.setBackground(SystemColor.control);
        this.setTitle("Select digital certificate");
        this.setResizable(false);

        // Center the dialog in the screen
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        Dimension dialogSize = this.getSize();
        int centerPosX = (screenSize.width - dialogSize.width) / 2;
        int centerPosY = (screenSize.height - dialogSize.height) / 2;
        setLocation(centerPosX, centerPosY);

        // Initialize certificate keystore file label
        mChooseCertFileLabel.setText(
        	"Please select your certificate keystore file (.PFX / .P12) :");
        mChooseCertFileLabel.setBounds(new Rectangle(10, 5, 350, 15));
        mChooseCertFileLabel.setFont(new Font("Dialog", 0, 12));

        // Initialize certificate keystore file name text field
        mCertFileNameTextField.setBounds(new Rectangle(10, 25, 315, 20));
        mCertFileNameTextField.setFont(new Font("DialogInput", 0, 12));
        mCertFileNameTextField.setEditable(false);
        mCertFileNameTextField.setBackground(SystemColor.control);

        // Initialize browse button
        mBrowseForCertButton.setText("Browse");
        mBrowseForCertButton.setBounds(new Rectangle(330, 25, 80, 20));
        mBrowseForCertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                browseForCertButton_actionPerformed();
            }
        });

        // Initialize password label
        mEnterPasswordLabel.setText("Enter the password for your private key:");
        mEnterPasswordLabel.setBounds(new Rectangle(10, 55, 350, 15));
        mEnterPasswordLabel.setFont(new Font("Dialog", 0, 12));

        // Initialize password text field
        mPasswordTextField.setBounds(new Rectangle(10, 75, 400, 20));
        mPasswordTextField.setFont(new Font("DialogInput", 0, 12));

        // Initialize sign button
        mSignButton.setText("Sign");
        mSignButton.setBounds(new Rectangle(110, 105, 75, 25));
        mSignButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                signButton_actionPerformed();
            }
        });

        // Initialize cancel button
        mCancelButton.setText("Cancel");
        mCancelButton.setBounds(new Rectangle(220, 105, 75, 25));
        mCancelButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                cancelButton_actionPerformed();
            }
        });

        // Add the initialized components into the dialog's content pane
        this.getContentPane().add(mChooseCertFileLabel, null);
        this.getContentPane().add(mCertFileNameTextField, null);
        this.getContentPane().add(mBrowseForCertButton, null);
        this.getContentPane().add(mEnterPasswordLabel, null);
        this.getContentPane().add(mPasswordTextField, null);
        this.getContentPane().add(mSignButton, null);
        this.getContentPane().add(mCancelButton, null);
        this.getRootPane().setDefaultButton(mSignButton);

        // Add some functionality for focusing the most appropriate
        // control when the dialog is shown
        this.addWindowListener(new WindowAdapter() {
            public void windowOpened(WindowEvent windowEvent) {
                String certFileName = mCertFileNameTextField.getText();
                if (certFileName != null && certFileName.length() != 0)
                    mPasswordTextField.requestFocus();
                else
                    mBrowseForCertButton.requestFocus();
            }
        });
    }

    /**
     * Called when the browse button is pressed.
     * Shows file choose dialog and allows the user to locate a PFX file.
     */
    private void browseForCertButton_actionPerformed() {
        JFileChooser fileChooser = new JFileChooser();
        PFXFileFilter pfxFileFilter = new PFXFileFilter();
        fileChooser.addChoosableFileFilter(pfxFileFilter);
        String certFileName = mCertFileNameTextField.getText();
        File directory = new File(certFileName).getParentFile();
        fileChooser.setCurrentDirectory(directory);
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            String selectedCertFile = fileChooser.getSelectedFile().getAbsolutePath();
            mCertFileNameTextField.setText(selectedCertFile);
        }
    }

    /**
     * Called when the sign button is pressed. Closses the dialog and sets the result
     * flag to true to indicate that the user is confirmed the information entered in
     * the dialog.
     */
    private void signButton_actionPerformed() {
        mResult = true;
        hide();
    }

    /**
     * Called when the cancel button is pressed. Closses the dialog and sets the
     * result flag to false that indicates that the dialog is canceled.
     */
    private void cancelButton_actionPerformed() {
        mResult = false;
        hide();
    }

    /**
     * @return the file name with full path to it where the dialog settings are stored.
     */
    private String getConfigFileName() {
        String configFileName = System.getProperty("user.home") +
            System.getProperty("file.separator") + CONFIG_FILE_NAME;
        return configFileName;
    }

    /**
     * Loads the dialog settings from the dialog configuration file. These settings
     * consist of a single value - the last used PFX file name with its full path.
     */
    private void loadSettings()
    throws IOException {
        // Load settings file
        String configFileName = getConfigFileName();
        FileInputStream configFileStream = new FileInputStream(configFileName);
        Properties configProps = new Properties();
        configProps.load(configFileStream);
        configFileStream.close();

        // Apply setings from the config file
        String lastCertificateFileName =
            configProps.getProperty(PFX_FILE_NAME_KEY);
        if (lastCertificateFileName != null)
            mCertFileNameTextField.setText(lastCertificateFileName);
        else
            mCertFileNameTextField.setText("");
    }

    /**
     * Saves the dialog settings to the dialog configuration file. These settings
     * consist of a single value - the last used PFX file name with its full path.
     */
    private void saveSettings()
    throws IOException {
        // Create a list of settings to store in the config file
        Properties configProps = new Properties();
        String currentCertificateFileName = mCertFileNameTextField.getText();
        configProps.setProperty(PFX_FILE_NAME_KEY, currentCertificateFileName);

        // Save the settings in the config file
        String configFileName = getConfigFileName();
        FileOutputStream configFileStream = new FileOutputStream(configFileName);
        configProps.store(configFileStream, "");
        configFileStream.close();
    }

    /**
     * @return the PFX file selected by the user.
     */
    public String getCertificateFileName() {
        String certFileName = mCertFileNameTextField.getText();
        return certFileName;
    }

    /**
     * @return the password entered by the user.
     */
    public String getCertificatePassword() {
        String password = mPasswordTextField.getText();
        return password;
    }

    /**
     * Shows the dialog and allows the user to choose a PFX file and enter a password.
     * @return true if the user click sign button or false if the user cancel the
     * dialog.
     */
    public boolean run() {
        try {
            loadSettings();
        } catch (IOException ioex) {
            // Loading settings failed. Can not handle this. Do nothing
        }

        setModal(true);
        show();

        try {
            if (mResult)
                saveSettings();
        } catch (IOException ioex) {
            // Saving settings failed. Can not handle this. Do nothing.
        }

        return mResult;
    }

    /**
     * File filter class, intended to accept only .PFX and .P12 files.
     */
    private static class PFXFileFilter extends FileFilter {
        public boolean accept(File aFile) {
            if (aFile.isDirectory()) {
                return true;
            }

            String fileName = aFile.getName().toUpperCase();
            boolean accepted =
                (fileName.endsWith(".PFX") || fileName.endsWith(".P12"));
            return accepted;
        }

        public String getDescription() {
            return "PKCS#12 certificate keystore file with private key (.PFX, .P12)";
        }
    }

}
