/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cienencrypt;

import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.ContainerAdapter;
import java.awt.event.ContainerEvent;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import javax.swing.TransferHandler;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 *
 * @author Cien
 */
public class Encrypter extends javax.swing.JFrame {

    private final MainWindow main;
    private Util.ZipStatus currentZipStatus = null;
    private Util.CipherStatus currentCipherStatus = null;

    /**
     * Creates new form Encrypter
     *
     * @param main
     */
    public Encrypter(MainWindow main) {
        initComponents();
        this.main = main;
        publicKeyField.setDropTarget(new DropTarget() {
            @Override
            public synchronized void drop(DropTargetDropEvent dtde) {
                onPublicKeyDrop(dtde);
            }
        });
        directoryField.setDropTarget(new DropTarget() {
            @Override
            public synchronized void drop(DropTargetDropEvent dtde) {
                onDirectoryFieldDrop(dtde);
            }
        });
    }

    public MainWindow getMain() {
        return main;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        publicKeyField = new javax.swing.JTextArea();
        jLabel2 = new javax.swing.JLabel();
        directoryField = new javax.swing.JTextField();
        chooseDirButton = new javax.swing.JButton();
        encryptButton = new javax.swing.JButton();
        logLabel = new javax.swing.JLabel();

        setTitle("Encriptador");
        setResizable(false);
        addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentHidden(java.awt.event.ComponentEvent evt) {
                formComponentHidden(evt);
            }
        });

        jLabel1.setText("Chave Pública (Arraste ou Cole):");

        publicKeyField.setColumns(20);
        publicKeyField.setLineWrap(true);
        publicKeyField.setRows(5);
        jScrollPane1.setViewportView(publicKeyField);

        jLabel2.setText("Pasta para Encriptar (Arraste, Cole ou Escolha):");

        chooseDirButton.setText("...");
        chooseDirButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chooseDirButtonActionPerformed(evt);
            }
        });

        encryptButton.setText("Encriptar");
        encryptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encryptButtonActionPerformed(evt);
            }
        });

        logLabel.setFont(new java.awt.Font("Monospaced", 0, 12)); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(encryptButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(logLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(directoryField, javax.swing.GroupLayout.PREFERRED_SIZE, 480, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(chooseDirButton, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(directoryField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(chooseDirButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(encryptButton)
                    .addComponent(logLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void onDirectoryFieldDrop(DropTargetDropEvent event) {
        try {
            event.acceptDrop(DnDConstants.ACTION_COPY);

            List<File> files = (List<File>) event.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
            if (files.size() != 1) {
                Toolkit.getDefaultToolkit().beep();
                return;
            }

            File f = files.get(0);
            if (!f.isDirectory()) {
                Toolkit.getDefaultToolkit().beep();
                return;
            }

            directoryField.setText(f.getAbsolutePath());
        } catch (UnsupportedFlavorException | IOException ex) {
            ex.printStackTrace();
            Toolkit.getDefaultToolkit().beep();
        }
    }

    private void onPublicKeyDrop(DropTargetDropEvent event) {
        event.acceptDrop(DnDConstants.ACTION_COPY);
        try {
            List<File> files = (List<File>) event.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
            if (files.size() != 1) {
                Toolkit.getDefaultToolkit().beep();
                return;
            }

            File f = files.get(0);
            if (!f.isFile()) {
                Toolkit.getDefaultToolkit().beep();
                return;
            }

            if (f.length() > 5000) {
                Toolkit.getDefaultToolkit().beep();
                return;
            }

            String key = Util.readFile(f);

            if (key == null) {
                Toolkit.getDefaultToolkit().beep();
                return;
            }

            publicKeyField.setText(key);
        } catch (UnsupportedFlavorException | IOException ex) {
            ex.printStackTrace();
            Toolkit.getDefaultToolkit().beep();
        }
    }

    private void formComponentHidden(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentHidden
        if (currentZipStatus != null) {
            currentZipStatus.setCancelled(true);
            currentZipStatus = null;
        }

        if (currentCipherStatus != null) {
            currentCipherStatus.setCancelled(true);
            currentCipherStatus = null;
        }

        publicKeyField.setText("");
        directoryField.setText("");
        logLabel.setText("");

        encryptButton.setEnabled(true);
        publicKeyField.setEditable(true);
        directoryField.setEditable(true);
        chooseDirButton.setEnabled(true);

        main.setLocationRelativeTo(null);
        main.setVisible(true);
    }//GEN-LAST:event_formComponentHidden

    private void chooseDirButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chooseDirButtonActionPerformed
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogType(JFileChooser.OPEN_DIALOG);
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fileChooser.addActionListener((e) -> {
            File f = fileChooser.getSelectedFile();

            if (f == null) {
                return;
            }

            if (!f.isDirectory()) {
                Toolkit.getDefaultToolkit().beep();
                return;
            }

            directoryField.setText(f.getAbsolutePath());
        });
        fileChooser.showOpenDialog(this);
    }//GEN-LAST:event_chooseDirButtonActionPerformed

    private void encryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encryptButtonActionPerformed
        String publicKey = publicKeyField.getText();

        try {

            byte[] keyBytes = Util.fromBase64(publicKey);

            PublicKey key = Util.toPublicKey(keyBytes);
            File directory = new File(directoryField.getText());

            if (!directory.isDirectory()) {
                Toolkit.getDefaultToolkit().beep();
                logLabel.setText("Pasta inválida ou ausente.");
                return;
            }

            JFileChooser resultChooser = new JFileChooser(directory.getAbsoluteFile().getParentFile());
            resultChooser.setDialogType(JFileChooser.SAVE_DIALOG);
            resultChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            resultChooser.setFileFilter(new FileNameExtensionFilter("Encrypted ZIP (.ezip)", "ezip"));
            resultChooser.setSelectedFile(new File(directory.getName()));
            resultChooser.addActionListener((e) -> {
                new Thread(() -> {

                    try {
                        File result = resultChooser.getSelectedFile();
                        if (result == null || e.getActionCommand().equals("CancelSelection")) {
                            return;
                        }
                        
                        disableFields();

                        String path = null;
                        if (!result.getName().endsWith(".ezip")) {
                            path = result.getAbsolutePath();
                            result = new File(path + ".ezip");
                        }
                        
                        if (result.exists() && result.isFile()) {
                            if (path == null) {
                                path = result.getAbsolutePath();
                                path = path.substring(0, path.length() - ".ezip".length());
                            }

                            int count = 0;
                            File target = null;
                            while ((target = new File(path + " (" + count + ").ezip")).exists()) {
                                count++;
                            }
                            result = target;
                        }

                        //zip
                        Util.ZipStatus status = new Util.ZipStatus() {
                            @Override
                            public void onStatusChanged() {
                                logLabel.setText("Compactando - " + getPercent() + "%: " + Util.fit(getStatus(), 35));
                            }
                        };

                        currentZipStatus = status;

                        File zip = Util.folderToZip(directory, status);

                        if (status.isCancelled()) {
                            zip.delete();
                            return;
                        }

                        //encrypt
                        Util.CipherStatus cipherStatus = new Util.CipherStatus() {
                            @Override
                            public void onStatusChanged() {
                                logLabel.setText("Criptografando - " + getPercent() + "%");
                            }
                        };

                        currentCipherStatus = cipherStatus;

                        Util.encryptFile(zip, result, key, cipherStatus);

                        if (cipherStatus.isCancelled()) {
                            zip.delete();
                            result.delete();
                            return;
                        }

                        logLabel.setText("Completo - " + Util.fit(result.getAbsolutePath(), 35));

                        currentCipherStatus = null;

                    } catch (IOException | GeneralSecurityException ex) {
                        logLabel.setText("Erro: " + ex.getMessage());
                        Toolkit.getDefaultToolkit().beep();
                        ex.printStackTrace();
                    } finally {
                        enableFields();
                    }
                }).start();
            });
            resultChooser.showSaveDialog(this);

        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            ex.printStackTrace();
            Toolkit.getDefaultToolkit().beep();
            logLabel.setText("Chave pública inválida ou ausente.");
        }
    }//GEN-LAST:event_encryptButtonActionPerformed

    private void enableFields() {
        encryptButton.setEnabled(true);
        publicKeyField.setEditable(true);
        directoryField.setEditable(true);
        chooseDirButton.setEnabled(true);
    }

    private void disableFields() {
        encryptButton.setEnabled(false);
        publicKeyField.setEditable(false);
        directoryField.setEditable(false);
        chooseDirButton.setEnabled(false);
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton chooseDirButton;
    private javax.swing.JTextField directoryField;
    private javax.swing.JButton encryptButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel logLabel;
    private javax.swing.JTextArea publicKeyField;
    // End of variables declaration//GEN-END:variables
}
