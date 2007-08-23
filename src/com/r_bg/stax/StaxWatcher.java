package com.r_bg.stax;

import javax.xml.stream.XMLStreamReader;

public interface StaxWatcher {
	/**
	 * Insert a C14n if needed
	 * @param reader
	 * @return a StreamFilter to be notified for the life of the element and all
	 * subelements.
	 */
	public StaxWorker watch(XMLStreamReader reader, StaxSignatureValidator sig);
}
