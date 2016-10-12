package org.apache.xml.security.test.stax.utils;

import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.JavaUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class KeyLoader {
    private static final String BASEDIR = System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
    private static final String SEP = System.getProperty("file.separator");

    private static DocumentBuilder documentBuilder;

    static {
        try {
            documentBuilder = XMLUtils.createDocumentBuilder(false);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    private static String getControlFilePath(String fileName) {
        return BASEDIR + SEP + "src" + SEP + "test" + SEP + "resources" +
                SEP + "org" + SEP + "apache" + SEP + "xml" + SEP + "security" +
                SEP + "keys" + SEP + "content" +
                SEP + fileName;
    }

    public static PublicKey loadPublicKey(String filePath, String algorithm) throws Exception {
        String fileData = new String(JavaUtils.getBytesFromFile(getControlFilePath(filePath)));
        byte[] keyBytes = Base64.decode(fileData);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(keySpec);
    }

    public static Document loadXML(String fileName) throws Exception {
        return documentBuilder.parse(new FileInputStream(getControlFilePath(fileName)));
    }

}
