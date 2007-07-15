package com.r_bg.stax;

import javax.xml.stream.XMLStreamReader;

public interface StaxWorker {
	public StaxWorker read(XMLStreamReader reader);
	public StaxWatcher remove();
}
