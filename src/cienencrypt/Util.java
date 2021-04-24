/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cienencrypt;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Cien
 */
public class Util {

    public static final int BUFFER_SIZE = 65536;

    public static abstract class CipherStatus {

        private int percent = 0;
        private boolean cancelled = false;

        public CipherStatus() {

        }

        public int getPercent() {
            return percent;
        }

        public void setPercent(int percent) {
            this.percent = percent;
            if (!cancelled) {
                onStatusChanged();
            }
        }

        public boolean isCancelled() {
            return cancelled;
        }

        public void setCancelled(boolean cancelled) {
            this.cancelled = cancelled;
        }

        public abstract void onStatusChanged();
    }

    public static abstract class ZipStatus {

        private String status = "";
        private int percent = 0;
        private boolean cancelled = false;

        public ZipStatus() {

        }

        public String getStatus() {
            return status;
        }

        public int getPercent() {
            return percent;
        }

        public void setPercent(int percent) {
            this.percent = percent;
            if (!cancelled) {
                onStatusChanged();
            }
        }

        public void setStatus(String status) {
            this.status = status;
            if (!cancelled) {
                onStatusChanged();
            }
        }

        public boolean isCancelled() {
            return cancelled;
        }

        public void setCancelled(boolean cancelled) {
            this.cancelled = cancelled;
        }

        public abstract void onStatusChanged();

    }

    public static String fit(String st, int length) {
        if (st.length() <= (length + 3)) {
            return st;
        }
        return "..." + st.substring(st.length() - (length + 3));
    }

    private static String getRelative(File parent, File folder) {
        return folder.getAbsolutePath().substring(parent.getAbsolutePath().length() + 1).replace('\\', '/');
    }

    private static List<File> getAllFilesAndFolders(File f, List<File> list) {
        list.add(f.getAbsoluteFile());
        if (f.isDirectory()) {
            for (File g : f.listFiles()) {
                getAllFilesAndFolders(g.getAbsoluteFile(), list);
            }
        }
        return list;
    }

    public static void decryptFile(File file, File result, PrivateKey pv, CipherStatus status) throws GeneralSecurityException, IOException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, pv);

        int lastPercent;
        int percent = 0;
        long totalRead = 0;

        if (status.isCancelled()) {
            return;
        }

        try (FileInputStream input = new FileInputStream(file);
                FileOutputStream output = new FileOutputStream(result)) {

            byte[] keySizeBytes = new byte[Integer.BYTES];
            if (input.read(keySizeBytes) != keySizeBytes.length) {
                throw new IOException("Arquivo Corrompido.");
            }
            totalRead += Integer.BYTES;

            int keySize = ByteBuffer.wrap(keySizeBytes).getInt();

            byte[] encryptedKeyBytes = new byte[keySize];
            if (input.read(encryptedKeyBytes) != encryptedKeyBytes.length) {
                throw new IOException("Arquivo Corrompido.");
            }
            totalRead += keySize;

            byte[] keyBytes = rsa.doFinal(encryptedKeyBytes);
            SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

            if (status.isCancelled()) {
                return;
            }

            try {
                Cipher aes = Cipher.getInstance("AES");
                aes.init(Cipher.DECRYPT_MODE, aesKey);

                byte[] sizeBytes = new byte[Integer.BYTES];

                while (input.read(sizeBytes) == sizeBytes.length) {
                    totalRead += sizeBytes.length;

                    int size = ByteBuffer.wrap(sizeBytes).getInt();

                    byte[] encPart = new byte[size];

                    if (input.read(encPart) != encPart.length) {
                        throw new IOException("Arquivo Corrompido.");
                    }

                    totalRead += encPart.length;

                    byte[] decrypted = aes.doFinal(encPart);

                    output.write(decrypted);

                    lastPercent = percent;
                    percent = (int) (((totalRead * 1f) / (file.length() * 1f)) * 100f);

                    if (status.isCancelled()) {
                        return;
                    }

                    if (percent != lastPercent) {
                        status.setPercent(percent);
                    }

                }

            } catch (InvalidKeyException ex) {
                throw new IOException("Arquivo Corrompido.");
            }

        }
    }

    public static void encryptFile(File file, File result, PublicKey pk, CipherStatus status) throws GeneralSecurityException, IOException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, pk);

        try (FileInputStream input = new FileInputStream(file);
                FileOutputStream output = new FileOutputStream(result)) {

            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            SecretKey aesKey = generator.generateKey();

            Cipher aes = Cipher.getInstance("AES");
            aes.init(Cipher.ENCRYPT_MODE, aesKey);

            byte[] encryptedKey = rsa.doFinal(aesKey.getEncoded());

            output.write(ByteBuffer.allocate(4).putInt(encryptedKey.length).array());
            output.write(encryptedKey);

            byte[] buf = new byte[BUFFER_SIZE];
            int read;
            int lastPercent;
            long totalRead = 0;
            int percent = 0;

            while ((read = input.read(buf)) != -1) {
                totalRead += read;

                lastPercent = percent;
                percent = (int) (((totalRead * 1f) / (file.length() * 1f)) * 100f);

                if (lastPercent != percent) {
                    status.setPercent(percent);
                }

                if (status.isCancelled()) {
                    result.deleteOnExit();
                    return;
                }

                byte[] encrypted = aes.doFinal(buf, 0, read);

                output.write(ByteBuffer.allocate(4).putInt(encrypted.length).array());
                output.write(encrypted);

            }

        }
    }

    public static void zipToFolder(File zip, File folder, ZipStatus st) throws IOException {
        List<String> entryList = new ArrayList<>();

        try (ZipInputStream zipRead = new ZipInputStream(new BufferedInputStream(new FileInputStream(zip)))) {
            int entries = 0;
            st.setStatus("Escaneando... (0 Entradas)");
            ZipEntry entry;
            while ((entry = zipRead.getNextEntry()) != null) {
                entries++;
                if (!entry.isDirectory()) {
                    entryList.add(entry.getName());
                }
                st.setStatus("Escaneando... (" + entries + " Entradas)");
            }
        }
        
        if (st.isCancelled()) {
            return;
        }

        try (ZipInputStream zipRead = new ZipInputStream(new BufferedInputStream(new FileInputStream(zip)))) {
            ZipEntry entry;
            int entries = 0;
            int percent = 0;
            while ((entry = zipRead.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    new File(folder, entry.getName()).mkdirs();
                    continue;
                }

                long entrySize;
                if (entry.getExtra() != null) {
                    entrySize = ByteBuffer.wrap(entry.getExtra()).getLong();
                } else {
                    entrySize = -1;
                }

                File extract = new File(folder, entry.getName());
                extract.getAbsoluteFile().getParentFile().mkdirs();

                long totalRead = 0;
                int read;
                int lastPercentExtraction;
                int percentExtraction = 0;
                byte[] buf = new byte[BUFFER_SIZE];
                try (FileOutputStream out = new FileOutputStream(extract)) {
                    while ((read = zipRead.read(buf)) != -1) {
                        totalRead += read;

                        lastPercentExtraction = percentExtraction;
                        percentExtraction = (int) (((totalRead * 1f) / (entrySize * 1f)) * 100f);
                        
                        out.write(buf, 0, read);

                        if (lastPercentExtraction != percentExtraction) {
                            if (entrySize == -1) {
                                st.setStatus("Extraindo - " + percent + "%: " + fit(entry.getName(), 25));
                            } else {
                                st.setStatus("Extraindo - " + percent + "%: " + fit(entry.getName(), 25) + " (" + percentExtraction + "%)");
                            }
                        }
                        
                        if (st.isCancelled()) {
                            return;
                        }
                        
                    }
                }

                entries++;
                percent = (int) (((entries * 1f) / (entryList.size() * 1f)) * 100f);
            }
        }
    }

    public static File folderToZip(File folder, ZipStatus st) throws IOException {

        st.setPercent(0);
        st.setStatus("Escaneando...");

        List<File> list = getAllFilesAndFolders(folder, new ArrayList<>());

        st.setPercent(100);
        st.setStatus("Iniciando...");

        File zipFile = File.createTempFile(UUID.randomUUID().toString(), ".zip");

        System.out.println(zipFile.getName());

        try (ZipOutputStream zipOut
                = new ZipOutputStream(
                        new BufferedOutputStream(
                                new FileOutputStream(
                                        zipFile), BUFFER_SIZE),
                        StandardCharsets.UTF_8)) {

            int filesDone = 0;

            for (File f : list) {

                st.setPercent((int) (((filesDone * 1f) / (list.size() * 1f)) * 100f));

                if (!f.exists()) {
                    filesDone++;
                    continue;
                }

                if (f.isDirectory()) {
                    st.setPercent(100);
                    filesDone++;
                    zipOut.putNextEntry(new ZipEntry(getRelative(folder.getParentFile(), f) + "/"));
                    continue;
                }

                ZipEntry entry = new ZipEntry(getRelative(folder.getParentFile(), f));
                entry.setExtra(ByteBuffer.allocate(8).putLong(f.length()).array());
                zipOut.putNextEntry(entry);

                try (FileInputStream input = new FileInputStream(f)) {
                    long written = 0;
                    int percent = 0;
                    int lastPercent = 0;
                    int r;

                    byte[] buf = new byte[BUFFER_SIZE];

                    while ((r = input.read(buf)) != -1) {

                        if (st.isCancelled()) {
                            zipFile.deleteOnExit();
                            return zipFile;
                        }

                        written += r;
                        zipOut.write(buf, 0, r);

                        lastPercent = percent;
                        percent = (int) (((written * 1f) / (f.length() * 1f)) * 100f);

                        if (lastPercent != percent) {
                            st.setStatus(f.getAbsolutePath() + " (" + percent + "%)");
                        }
                    }

                    zipOut.closeEntry();
                    zipOut.flush();

                }

                filesDone++;
            }
        }

        st.setPercent(100);
        st.setStatus("Zip Finalizado.");

        if (st.isCancelled()) {
            zipFile.deleteOnExit();
            return zipFile;
        }

        return zipFile;
    }

    public static PublicKey toPublicKey(byte[] bytes) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    }

    public static PrivateKey toPrivateKey(byte[] bytes) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String str) {
        return Base64.getDecoder().decode(str);
    }

    public static void writeToFile(File f, String text) {
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8))) {
            writer.write(text);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static String readFile(File f) {
        try {
            StringBuilder b;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
                b = new StringBuilder();
                int r;
                char[] buf = new char[4096];
                while ((r = reader.read(buf)) != -1) {
                    for (int i = 0; i < r; i++) {
                        if (buf[i] == '\r' || buf[i] == '\n') {
                            continue;
                        }
                        b.append(buf[i]);
                    }
                }
            }
            return b.toString();
        } catch (IOException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    private Util() {

    }
}
