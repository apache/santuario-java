package com.r_bg.stax;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.DigesterOutputStream;

class Constants {
	public static final String DS_URI="http://www.w3.org/2000/09/xmldsig#";
}




class ReferenceWorker implements StaxWorker, Reference, DigestResultListener {	
	boolean readDigestValue=false;
	String uri;
	String c14nType;
	String digestMethod;
	byte[] digestValue;
	byte[] calculateDigestValue;
	boolean correct=false;
	DigesterOutputStream os;
	private String id;
	private String type;
	public StaxWorker read(XMLStreamReader reader) {
		switch (reader.getEventType()) {
		
		case XMLStreamReader.START_ELEMENT: 
			if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
			  String name=reader.getLocalName();
			  if (name.equals("Reference") ) {
				uri=reader.getAttributeValue(null,"URI");
				id=reader.getAttributeValue(null,"Id");
				type=reader.getAttributeValue(null,"Type");
			  }
			  if (name.equals("DigestMethod")) {
				digestMethod=reader.getAttributeValue(null,"Algorithm");				 
				try {
					MessageDigest ms = MessageDigest.getInstance(
							JCEMapper.translateURItoJCEID(digestMethod));
					os=new DigesterOutputStream(ms);
				} catch (NoSuchAlgorithmException e) {
					//TODO: Better error handling.
					e.printStackTrace();
				}				
			  }
			  if (name.equals("DigestValue")) {
				readDigestValue=true;
			  }			
			}
			break;
		case XMLStreamReader.END_ELEMENT: 
		    if (Constants.DS_URI.equals(reader.getNamespaceURI())) {
			  if (reader.getLocalName().equals("DigestValue")) {
				readDigestValue=false;
			  }
		    }
		    break;
		case XMLStreamReader.CHARACTERS:		
			if (readDigestValue) {
				try {
					digestValue=Base64.decode(reader.getText());
				} catch (Base64DecodingException e) {
					e.printStackTrace();
				}
		     }
			break;
		}
		return null;
	}
	public StaxWatcher remove() {		
	    if (uri != null && !uri.isEmpty()) {
		return new IdWatcher(uri.substring(1),this,os);
	    } else {
		return null;
	    }
	}
	/* (non-Javadoc)
	 * @see com.r_bg.stax.DigestResultListener#setResult(byte[])
	 */
	public void setResult(byte[] result) {
		calculateDigestValue=os.getDigestValue();
		correct=Arrays.equals(calculateDigestValue, digestValue);
		
	}
	public List getTransforms() {
		// TODO Auto-generated method stub
		return null;
	}
	public DigestMethod getDigestMethod() {
		return null;
	}
	public String getId() {
		return id;
	}
	public byte[] getDigestValue() {	
		return digestValue;
	}
	public byte[] getCalculatedDigestValue() {
		return calculateDigestValue;
	}
	public boolean validate(XMLValidateContext validateContext) throws XMLSignatureException {
		return correct;
	}
	public Data getDereferencedData() {
		// TODO Auto-generated method stub
		return null;
	}
	public InputStream getDigestInputStream() {
		// TODO Auto-generated method stub
		return null;
	}
	public String getURI() {
		return uri;
	}
	public String getType() {
		return type;
	}
	public boolean isFeatureSupported(String feature) {
		// TODO Auto-generated method stub
		return false;
	}
	
}
class SignedInfoWorker implements StaxWorker, SignedInfo, DigestResultListener {
	ByteArrayOutputStream bos=new ByteArrayOutputStream(); 
	boolean initial=true;
	C14nWorker c14n=new C14nWorker(this,bos);
	List<ReferenceWorker> references=new ArrayList<ReferenceWorker>();
	String signatureMethod;
	String c14nMethod;
	private String id;
	public StaxWorker read(XMLStreamReader reader) {
		if (reader.getEventType()==XMLStreamReader.START_ELEMENT && Constants.DS_URI.equals(reader.getNamespaceURI())) {
			String name=reader.getLocalName();
			if (name.equals("SignedInfo") ) {
				id=reader.getAttributeValue(null,"Id");
			}
			if (name.equals("Reference") ) {
				ReferenceWorker r=new ReferenceWorker();
				references.add(r);
				return r;			
			}
			if (name.equals("SignatureMethod")) {
				signatureMethod=reader.getAttributeValue(null,"Algorithm");
			}
			if (name.equals("CanonicalizationMethod")) {
				//TODO: Change c14n.
				c14nMethod=reader.getAttributeValue(null,"Algorithm");
			}
		}
		if (initial) {
			initial=false;
			return c14n;
		}
		
		return null;
	}

	public StaxWatcher remove() {
		return null;
	}

	public CanonicalizationMethod getCanonicalizationMethod() {
		return new CanonicalizationMethod() {
			public AlgorithmParameterSpec getParameterSpec() {
				return null;
			}
			public String getAlgorithm() {
				return c14nMethod;
			}
			public boolean isFeatureSupported(String feature) {
				return false;
			}
			public Data transform(Data data, XMLCryptoContext context) throws TransformException {
				throw new UnsupportedOperationException();
			}
			public Data transform(Data data, XMLCryptoContext context, OutputStream os) throws TransformException {
				throw new UnsupportedOperationException();
			}
		};
	}

	public SignatureMethod getSignatureMethod() {
		return new SignatureMethod() {
			public AlgorithmParameterSpec getParameterSpec() {
				return null;
			}
			public String getAlgorithm() {
				return signatureMethod;
			}
			public boolean isFeatureSupported(String feature) {
				return false;
			}
		};
	}

	public List getReferences() {
		return references;
	}

	public String getId() {
		return id;
	}

	public InputStream getCanonicalizedData() {
		// TODO Auto-generated method stub
		return null;
	}

	public boolean isFeatureSupported(String feature) {
		// TODO Auto-generated method stub
		return false;
	}

	public void setResult(byte[] result) {		
		
	}
	
}
class SignatureWatcher implements StaxWatcher {	
	public StaxWorker watch(XMLStreamReader reader, StaxSignatureVerificator sig) {
		String name=reader.getLocalName();
		String uri=reader.getNamespaceURI();
		if (name.equals("Signature") && 
				uri.equals(Constants.DS_URI)) {			
			XMLSignatureWorker s=new XMLSignatureWorker();
			sig.addSignature(s);
			return s;
		}
		
		return null;
	}
}

class SignatureValueWorker implements StaxWorker,XMLSignature.SignatureValue {		
	private String id;
	private byte[] signatureValue;
	private boolean readSignatureValue=false;
	public StaxWorker read(XMLStreamReader reader) {
		switch (reader.getEventType()) {
		  case XMLStreamReader.START_ELEMENT:
			if (Constants.DS_URI.equals(reader.getNamespaceURI())) {
				String name=reader.getLocalName();
				if (name.equals("SignatureValue") ) {
					id=reader.getAttributeValue(null,"Id");
					readSignatureValue=true;
				}
			}
			break;
		  case XMLStreamReader.END_ELEMENT: 
			if (Constants.DS_URI.equals(reader.getNamespaceURI())) {
				if (reader.getLocalName().equals("SignatureValue")) {
					readSignatureValue=false;
				}
			}
			break;
		  case XMLStreamReader.CHARACTERS:		
			if (readSignatureValue) {
				try {					
					signatureValue=Base64.decode(reader.getText());
				} catch (Base64DecodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		    	}
		    	break;
		}
		return null;
	}

	public StaxWatcher remove() {		
		return null;
	}

	public boolean isFeatureSupported(String feature) {
		return false;
	}

	public String getId() {
	    return id;
	}

	public byte[] getValue() {
	    return (byte[]) signatureValue.clone();
	}

	public boolean validate(XMLValidateContext validateContext) throws XMLSignatureException {
	    throw new UnsupportedOperationException();
	}
}

public class XMLSignatureWorker implements StaxWorker,XMLSignature {		
	SignedInfoWorker si;
	SignatureValueWorker sv;
	private String id;
	public StaxWorker read(XMLStreamReader reader) {
		switch (reader.getEventType()) {
		  case XMLStreamReader.START_ELEMENT:
			if (Constants.DS_URI.equals(reader.getNamespaceURI())) {
				String name=reader.getLocalName();
				if (name.equals("Signature") ) {
					id=reader.getAttributeValue(null,"Id");
				}
				if (name.equals("SignedInfo") ) {
					si=new SignedInfoWorker();
					return si;			
				}
				if (name.equals("SignatureValue")) {
					sv=new SignatureValueWorker();
					return sv;
				}			
			}
			break;
	    	}
		return null;
	}
	
	public StaxWatcher remove() {		
		return null;
	}
	public boolean validate(XMLValidateContext validateContext) throws XMLSignatureException {
		StaxValidateContext ctx=(StaxValidateContext) validateContext;
		try {
			for (Reference ref: si.references) {
				if (!ref.validate(ctx))
					return false;
			}
			SignatureAlgorithm sa=new SignatureAlgorithm(si.signatureMethod);
			// get key from KeySelector
                        KeySelectorResult ksr = null;
                        try {
                            ksr = ctx.getKeySelector().select(getKeyInfo(), 
				KeySelector.Purpose.VERIFY, 
				getSignedInfo().getSignatureMethod(), 
				validateContext);
                        } catch (KeySelectorException kse) {
                            throw new XMLSignatureException(kse);
                        }
			sa.initVerify(ksr.getKey());
			sa.update(si.bos.toByteArray());			
			return sa.verify(sv.getValue());
		} catch (org.apache.xml.security.signature.XMLSignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}
	public KeyInfo getKeyInfo() {
		// TODO Auto-generated method stub
		return null;
	}
	public SignedInfo getSignedInfo() {
		return si;
	}
	public List getObjects() {
		// TODO Auto-generated method stub
		return null;
	}
	public String getId() {
		return id;
	}
	public SignatureValue getSignatureValue() {
		return sv;
	}
	public void sign(XMLSignContext signContext) throws MarshalException, XMLSignatureException {
		// TODO Auto-generated method stub
		
	}
	public KeySelectorResult getKeySelectorResult() {
		// TODO Auto-generated method stub
		return null;
	}
	public boolean isFeatureSupported(String feature) {
		// TODO Auto-generated method stub
		return false;
	}
	
}
