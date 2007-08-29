package com.r_bg.stax;

import java.io.IOException;
import java.io.OutputStream;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.exceptions.Base64DecodingException;

public class StaxBase64TransformWorker implements StaxWorker {
    DigestResultListener re;
    OutputStream os;

    public StaxBase64TransformWorker(DigestResultListener re, OutputStream os) {
	this.os = os;
	this.re = re;
    }

    public StaxWorker read(XMLStreamReader reader) {
        switch (reader.getEventType()) {
            case XMLStreamReader.CHARACTERS:
		String text = reader.getText();
		System.out.println(text);
		try {
	            Base64.decode(text, os);
		} catch (Base64DecodingException e) {
		    e.printStackTrace();
		} catch (IOException e) {
		    e.printStackTrace();
		}
	        break;
        }
	return null;
    }

    public StaxWatcher remove() {
	re.setResult(null);
	return null;
    }
}
