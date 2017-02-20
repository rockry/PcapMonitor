package packetProcessor;

import java.io.PrintStream;

import jpcap.packet.Packet;
import jpcap.packet.W80211Packet;

public class SystemWriter implements IPacketWriter {

	private PrintStream printStream;

	public SystemWriter(PrintStream output) {
		printStream = output;
	}

	@Override
	public void close() {
		// Intentionally don't take any action. We shall not close the
		// System.out stream
	}

	@Override
	public void writePacket(Packet packet) {
		if (packet.datalink instanceof W80211Packet) {
			printStream.println(packet.toString() + " "+ packet.datalink.toString());
		} else {
			printStream.println(packet.toString());
		}
	}

}
