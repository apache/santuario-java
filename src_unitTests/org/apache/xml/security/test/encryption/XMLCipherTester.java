/*
 * The Apache Software License, Version 1.1
 *
 *
 * Copyright (c) 1999 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "<WebSig>" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation and was
 * originally based on software copyright (c) 2001, Institute for
 * Data Communications Systems, <http://www.nue.et-inf.uni-siegen.de/>.
 * The development of this software was partly funded by the European
 * Commission in the <WebSig> project in the ISIS Programme.
 * For more information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */
package org.apache.xml.security.test.encryption;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.encryption.CipherData;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.IdResolver;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.serialize.DOMSerializer;
import org.apache.xml.serialize.Method;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


/**
 *
 * @author  Axl Mattheus
 * @author  Berin Lautenbach
 */
public class XMLCipherTester extends TestCase {

	/** {@link org.apache.commons.logging} logging facility */
    static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(XMLCipherTester.class.getName());
    
    private String documentName;
    private String elementName;
    private String elementIndex;
    private XMLCipher cipher;

	private String tstBase64EncodedString;

    public XMLCipherTester(String test) {
       super(test);
    }

    protected void setUp() {
        documentName = System.getProperty("org.apache.xml.enc.test.doc",
            "./build.xml");
        elementName = System.getProperty("org.apache.xml.enc.test.elem",
            "path");
        elementIndex = System.getProperty("org.apache.xml.enc.test.idx",
            "0");

		tstBase64EncodedString = new String("YmNkZWZnaGlqa2xtbm9wcRrPXjQ1hvhDFT+EdesMAPE4F6vlT+y0HPXe0+nAGLQ8");
    }

    protected void tearDown() {
    }

    private Document document() {
        Document d = null;
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            File f = new File(documentName);
            d = db.parse(f);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }

        return (d);
    }

    private String element() {
        return (elementName);
    }

    private int index() {
        int result = -1;

        try {
            result = Integer.parseInt(elementIndex);
        } catch (NumberFormatException nfe) {
            nfe.printStackTrace();
            System.exit(-1);
        }

        return (result);
    }

	/**
	 * Test encryption using a generated AES 128 bit key that is
	 * encrypted using a AES 192 bit key.  Then reverse using the KEK
	 */

	public void testAES128ElementAES192KWCipherUsingKEK() {

		Document d = document(); // source
		Document ed = null;
		Document dd = null;
		Element e = (Element) d.getElementsByTagName(element()).item(index());
		Element ee = null;

		String source = null;
		String target = null;

        try {

			source = toString(d);

			// Set up a Key Encryption Key
			byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
			Key kek = new SecretKeySpec(bits192, "AES");

			// Generate a traffic key
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			keygen.init(128);
			Key key = keygen.generateKey();

            cipher = XMLCipher.getInstance(XMLCipher.AES_192_KeyWrap);
			cipher.init(XMLCipher.WRAP_MODE, kek);
			EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
			EncryptedData builder = cipher.getEncryptedData();

			KeyInfo builderKeyInfo = builder.getKeyInfo();
			if (builderKeyInfo == null) {
				builderKeyInfo = new KeyInfo(d);
				builder.setKeyInfo(builderKeyInfo);
			}

			builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);

            //decrypt
			key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, null);
			cipher.setKEK(kek);
			dd = cipher.doFinal(ed, ee);

            target = toString(dd);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Assert.assertEquals(source, target);
    }
  
	/**
	 * Test encryption using a generated AES 256 bit key that is
	 * encrypted using an RSA key.  Reverse using KEK
	 */

	public void testAES128ElementRSAKWCipherUsingKEK() {

		Document d = document(); // source
		Document ed = null;
		Document dd = null;
		Element e = (Element) d.getElementsByTagName(element()).item(index());
		Element ee = null;

		String source = null;
		String target = null;

        try {

			source = toString(d);

            // Generate an RSA key
            KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
            KeyPair kp = rsaKeygen.generateKeyPair();
            PrivateKey priv = kp.getPrivate();
            PublicKey pub = kp.getPublic();
            
			// Generate a traffic key
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			keygen.init(256);
			Key key = keygen.generateKey();

            
            cipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
			cipher.init(XMLCipher.WRAP_MODE, pub);
			EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
			EncryptedData builder = cipher.getEncryptedData();

			KeyInfo builderKeyInfo = builder.getKeyInfo();
			if (builderKeyInfo == null) {
				builderKeyInfo = new KeyInfo(d);
				builder.setKeyInfo(builderKeyInfo);
			}

			builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);
            log.debug("Encrypted document");
            log.debug(toString(ed));


            //decrypt
			key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, null);
			cipher.setKEK(priv);
			dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            log.debug("Output document");
            log.debug(target);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Assert.assertEquals(source, target);
    }

	/**
	 * Test encryption using a generated AES 192 bit key that is
	 * encrypted using a 3DES key.  Then reverse by decrypting 
	 * EncryptedKey by hand
	 */

	public void testAES192ElementAES256KWCipher() {

		Document d = document(); // source
		Document ed = null;
		Document dd = null;
		Element e = (Element) d.getElementsByTagName(element()).item(index());
		Element ee = null;

		String source = null;
		String target = null;

        try {

			source = toString(d);

			// Set up a Key Encryption Key
			byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
            DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            Key kek = keyFactory.generateSecret(keySpec);

			// Generate a traffic key
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			keygen.init(192);
			Key key = keygen.generateKey();

            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES_KeyWrap);
			cipher.init(XMLCipher.WRAP_MODE, kek);
			EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
			EncryptedData builder = cipher.getEncryptedData();

			KeyInfo builderKeyInfo = builder.getKeyInfo();
			if (builderKeyInfo == null) {
				builderKeyInfo = new KeyInfo(d);
				builder.setKeyInfo(builderKeyInfo);
			}

			builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);

            //decrypt
			key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance();
            cipher.init(XMLCipher.DECRYPT_MODE, null);

			EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
			
			if(encryptedData == null) {
				System.out.println("ed is null");
			}
			else if (encryptedData.getKeyInfo() == null) {
				System.out.println("ki is null");
			}
			EncryptedKey ek = encryptedData.getKeyInfo().itemEncryptedKey(0);

			if (ek != null) {
				XMLCipher keyCipher = XMLCipher.getInstance();
				keyCipher.init(XMLCipher.UNWRAP_MODE, kek);
				key = keyCipher.decryptKey(ek, encryptedData.getEncryptionMethod().getAlgorithm());
			}

			// Create a new cipher just to be paranoid
			XMLCipher cipher3 = XMLCipher.getInstance();
			cipher3.init(XMLCipher.DECRYPT_MODE, key);
            dd = cipher3.doFinal(ed, ee);

            target = toString(dd);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Assert.assertEquals(source, target);
    }

    public void testTrippleDesElementCipher() {
        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        try {

			source = toString(d);

            // prepare for encryption
            byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
            DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey key = keyFactory.generateSecret(keySpec);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
			EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
			Assert.assertEquals(encryptedData.getEncryptionMethod().getAlgorithm(), 
								XMLCipher.TRIPLEDES);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Assert.assertEquals(source, target);
    }

    public void testAes128ElementCipher() {
        byte[] bits128 = {
            (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
            (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
            (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        Key key = new SecretKeySpec(bits128, "AES");

        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        try {

			source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
			EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
			Assert.assertEquals(encryptedData.getEncryptionMethod().getAlgorithm(), 
								XMLCipher.AES_128);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Assert.assertEquals(source, target);
    }

    public void testAes192ElementCipher() {
        byte[] bits192 = {
            (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
            (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
            (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
            (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
            (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        Key key = new SecretKeySpec(bits192, "AES");

        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        try {

			source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
			EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
			Assert.assertEquals(encryptedData.getEncryptionMethod().getAlgorithm(), 
								XMLCipher.AES_192);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Assert.assertEquals(source, target);
    }

    public void testAes265ElementCipher() {
        byte[] bits256 = {
            (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
            (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
            (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
            (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
            (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
            (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
            (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        Key key = new SecretKeySpec(bits256, "AES");

        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        try {

			source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
			EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
			Assert.assertEquals(encryptedData.getEncryptionMethod().getAlgorithm(), 
								XMLCipher.AES_256);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Assert.assertEquals(source, target);
    }

    /*
	 * Test case for when the entire document is encrypted and decrypted
	 * In this case the EncryptedData becomes the root element of the document
	 */

    public void testTrippleDesDocumentCipher() {
        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = d.getDocumentElement();
        Element ee = null;

        String source = null;
        String target = null;

        try {
			source = toString(d);

            // prepare for encryption
            byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
            DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey key = keyFactory.generateSecret(keySpec);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Assert.assertEquals(source, target);
    }

	/*
	 * Test a Cipher Reference
	 */

	public void testSameDocumentCipherReference() throws Exception {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();

		Document d = db.newDocument();

		Element docElement = d.createElement("EncryptedDoc");
		d.appendChild(docElement);

		// Create the XMLCipher object
		cipher = XMLCipher.getInstance();

		EncryptedData ed = 
			cipher.createEncryptedData(CipherData.REFERENCE_TYPE,
									   "#CipherTextId");
		EncryptionMethod em =
			cipher.createEncryptionMethod(XMLCipher.AES_128);

		ed.setEncryptionMethod(em);

		org.apache.xml.security.encryption.Transforms xencTransforms =
			cipher.createTransforms(d);
		ed.getCipherData().getCipherReference().setTransforms(xencTransforms);
		org.apache.xml.security.transforms.Transforms dsTransforms =
			xencTransforms.getDSTransforms();

		// An XPath transform
		XPathContainer xpc = new XPathContainer(d);
		xpc.setXPath("self::text()[parent::CipherText[@Id=\"CipherTextId\"]]");
		dsTransforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_XPATH, 
								  xpc.getElementPlusReturns());

		// Add a Base64 Transforms
		dsTransforms.addTransform(
								  org.apache.xml.security.transforms.Transforms.TRANSFORM_BASE64_DECODE);

		Element ee = cipher.martial(d, ed);

		docElement.appendChild(ee);

		// Add the cipher text
		Element encryptedElement = d.createElement("CipherText");
		encryptedElement.setAttributeNS(null, "Id", "CipherTextId");
		IdResolver.registerElementById(encryptedElement, "CipherTextId");
		encryptedElement.appendChild(d.createTextNode(tstBase64EncodedString));
		docElement.appendChild(encryptedElement);
		// dump(d);

		// Now the decrypt, with a brand new cipher
		XMLCipher cipherDecrypt = XMLCipher.getInstance();
        Key key = 
			new SecretKeySpec("abcdefghijklmnop".getBytes("ASCII"), "AES");

		cipherDecrypt.init(XMLCipher.DECRYPT_MODE, key);
		byte[] decryptBytes = cipherDecrypt.decryptToByteArray(ee);

        Assert.assertEquals(new String(decryptBytes, "ASCII"), 
							new String("A test encrypted secret"));

	}

    private void dump(Element element) {
        OutputFormat of = new OutputFormat();
        of.setIndenting(true);
        of.setMethod(Method.XML);
        of.setOmitDocumentType(true);
        of.setOmitXMLDeclaration(true);
        DOMSerializer serializer = new XMLSerializer(System.out, of);
        try {
            serializer.serialize(element);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    private void dump(Document document) {
        OutputFormat of = new OutputFormat();
        of.setIndenting(true);
        of.setMethod(Method.XML);
        of.setOmitDocumentType(true);
        of.setOmitXMLDeclaration(true);
        DOMSerializer serializer = new XMLSerializer(System.out, of);
        try {
            serializer.serialize(document);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

	/*
    private String toString(Element element) 
		           throws UnsupportedEncodingException {
        OutputFormat of = new OutputFormat();
        of.setIndenting(true);
        of.setEncoding("UTF-8");
        of.setMethod(Method.XML);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DOMSerializer serializer = new XMLSerializer(baos, of);
        try {
            serializer.serialize(element);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
        return (baos.toString("UTF-8"));
    }
    private String toString(Document document) 
	               throws  UnsupportedEncodingException {
        OutputFormat of = new OutputFormat();
        of.setIndenting(true);
		of.setEncoding("UTF-8");
        of.setMethod(Method.XML);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DOMSerializer serializer = new XMLSerializer(baos, of);
        try {
            serializer.serialize(document);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
        return (baos.toString("UTF-8"));
    }
	*/

	private String toString (Node n)
		throws Exception {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Canonicalizer c14n = Canonicalizer.getInstance
			(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);

		byte[] serBytes = c14n.canonicalizeSubtree(n);
		baos.write(serBytes);
		baos.close();

		return baos.toString("UTF-8");

	}
		
    private void toString(Document document, String outputFile) 
	               throws  UnsupportedEncodingException , FileNotFoundException {
        OutputFormat of = new OutputFormat();
        of.setIndenting(true);
		of.setEncoding("UTF-8");
        of.setMethod(Method.XML);
        FileOutputStream baos = new FileOutputStream(outputFile);
        DOMSerializer serializer = new XMLSerializer(baos, of);
        try {
            serializer.serialize(document);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }
   static {
      org.apache.xml.security.Init.init();
   }

}
