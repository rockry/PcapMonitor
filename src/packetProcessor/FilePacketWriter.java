package packetProcessor;

import jpcap.JpcapWriter;
import jpcap.packet.Packet;

/**
 * This class writes packets to files.
 */
public class FilePacketWriter implements IPacketWriter {

	/**
	 * File packet writer
	 */
	private JpcapWriter writer;

	/**
	 * Constructor
	 * 
	 * @param output
	 *            the writer used to write packets to file
	 */
	public FilePacketWriter(JpcapWriter output) {
		writer = output;
	}

	/**
	 * Write the specified packet to file
	 */
	@Override
	public void writePacket(Packet packet) {
		writer.writePacket(packet);

	}

	/**
	 * Close file
	 */
	@Override
	public void close() {
		writer.close();
	}

}
