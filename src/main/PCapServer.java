package main;

import android.util.Log;
import packetProcessor.IPacketReader;
import packetProcessor.NetworkInterfacePacketReader;
import pcapmonitor.JpcapTools;

public class PCapServer {

	private IPacketReader reader;

	public PCapServer(IPacketReader readerInstance) {
		this.reader = readerInstance;
	}

	public void start() {
		Log.e(JpcapTools.TAG, "Start listening for packets...");
		reader.startReadingPackets();
	}
	
	public void stop() {
		Log.e(JpcapTools.TAG, "Stop listening for packets...");
		if (reader != null && reader instanceof NetworkInterfacePacketReader) {
			Log.e(JpcapTools.TAG, "Enter something and press enter to stop reading: ");
			reader.stopReadingPackets();
		}
	}
}
