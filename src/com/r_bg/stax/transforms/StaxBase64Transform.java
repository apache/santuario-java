package com.r_bg.stax.transforms;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.utils.Base64;
import com.r_bg.stax.StaxData;

public class StaxBase64Transform extends TransformService {

    public void init(TransformParameterSpec params) 
	throws InvalidAlgorithmParameterException { 
	if (params != null) {
	    throw new InvalidAlgorithmParameterException("params must be null");
	}
    }

    public void init(XMLStructure parent, XMLCryptoContext context) 
	throws InvalidAlgorithmParameterException { 
	if (parent == null) {
	    throw new NullPointerException();
	}
    }

    public void marshalParams(XMLStructure parent, XMLCryptoContext context) 
	throws MarshalException {
	if (parent == null) {
	    throw new NullPointerException();
	}
    }

    public Data transform(Data data, XMLCryptoContext context) 
	throws TransformException {
	byte[] bytes = null;
	XMLStreamReader reader = ((StaxData) data).getXMLStreamReader();
        switch (reader.getEventType()) {
            case XMLStreamReader.CHARACTERS:
		String text = reader.getText();
		try {
	            bytes = Base64.decode(text);
		} catch (Exception e) {
		    throw new TransformException(e);
		}
	        break;
        }
	return new OctetStreamData(new ByteArrayInputStream(bytes));
    }

    public Data transform(Data data, XMLCryptoContext context, OutputStream os)
	throws TransformException {
	XMLStreamReader reader = ((StaxData) data).getXMLStreamReader();
        switch (reader.getEventType()) {
            case XMLStreamReader.CHARACTERS:
		String text = reader.getText();
		try {
	            Base64.decode(text, os);
		} catch (Exception e) {
		    throw new TransformException(e);
		}
	        break;
        }
	return null;
    }

    public AlgorithmParameterSpec getParameterSpec() {
	return null;
    }

    public boolean isFeatureSupported(String feature) {
	return false;
    }
}
