/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cienencrypt;

import java.awt.Toolkit;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 *
 * @author Cien
 */
public class RSAGenerator extends javax.swing.JFrame {

    private final MainWindow main;

    /**
     * Creates new form KeyGenerator
     *
     * @param main
     */
    public RSAGenerator(MainWindow main) {
        this.main = main;
        initComponents();
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
        jLabel2 = new javax.swing.JLabel();
        generateButton = new javax.swing.JButton();
        saveButton = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        publicKeyField = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        privateKeyField = new javax.swing.JTextArea();

        setTitle("Gerador de Chaves");
        setResizable(false);
        addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentHidden(java.awt.event.ComponentEvent evt) {
                formComponentHidden(evt);
            }
        });

        jLabel1.setText("Chave Pública:");

        jLabel2.setText("Chave Privada:");

        generateButton.setText("Gerar");
        generateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                generateButtonActionPerformed(evt);
            }
        });

        saveButton.setText("Salvar");
        saveButton.setEnabled(false);
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });

        publicKeyField.setEditable(false);
        publicKeyField.setColumns(20);
        publicKeyField.setLineWrap(true);
        publicKeyField.setRows(5);
        jScrollPane1.setViewportView(publicKeyField);

        privateKeyField.setEditable(false);
        privateKeyField.setColumns(20);
        privateKeyField.setLineWrap(true);
        privateKeyField.setRows(5);
        jScrollPane2.setViewportView(privateKeyField);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 508, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(jLabel2)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(generateButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(saveButton)))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(jScrollPane2))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(generateButton)
                    .addComponent(saveButton))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void formComponentHidden(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentHidden
        publicKeyField.setText("");
        privateKeyField.setText("");
        saveButton.setEnabled(false);
        generateButton.setEnabled(true);

        main.setLocationRelativeTo(null);
        main.setVisible(true);
    }//GEN-LAST:event_formComponentHidden

    private void generateButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_generateButtonActionPerformed
        generateButton.setEnabled(false);
        new Thread(() -> {
            try {
                KeyPair pair = Util.generateKeyPair();

                String pub = Util.toBase64(pair.getPublic().getEncoded());
                String priv = Util.toBase64(pair.getPrivate().getEncoded());

                SwingUtilities.invokeLater(() -> {
                    publicKeyField.setText(pub);
                    privateKeyField.setText(priv);

                    saveButton.setEnabled(true);
                });
            } finally {
                generateButton.setEnabled(true);
            }
        }, "Generate Keys Thread").start();

        publicKeyField.setText("Gerando...");
        privateKeyField.setText("Gerando...");
    }//GEN-LAST:event_generateButtonActionPerformed

    private void saveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveButtonActionPerformed
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogType(JFileChooser.SAVE_DIALOG);
        fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        fileChooser.setFileFilter(new FileNameExtensionFilter("Par de Chaves RSA (.key)", "key"));
        fileChooser.setSelectedFile(new File("Chaves RSA"));
        fileChooser.addActionListener((e) -> {

            try {

                File folder = fileChooser.getSelectedFile();
                if (folder == null) {
                    return;
                }

                if (!folder.isDirectory()) {
                    folder.mkdirs();
                }

                File pub = new File(folder, "publica.key");
                File priv = new File(folder, "privada.key");

                if (pub.exists()) {
                    int count = 0;
                    while ((pub = new File(folder, "publica (" + count + ").key")).exists()) {
                        count++;
                    }
                }
                
                if (priv.exists()) {
                    int count = 0;
                    while ((priv = new File(folder, "privada (" + count + ").key")).exists()) {
                        count++;
                    }
                }

                Util.writeToFile(pub, publicKeyField.getText());
                Util.writeToFile(priv, privateKeyField.getText());

            } catch (Exception ex) {
                ex.printStackTrace();
                Toolkit.getDefaultToolkit().beep();
            }

        });
        fileChooser.showSaveDialog(this);
    }//GEN-LAST:event_saveButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton generateButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextArea privateKeyField;
    private javax.swing.JTextArea publicKeyField;
    private javax.swing.JButton saveButton;
    // End of variables declaration//GEN-END:variables
}
