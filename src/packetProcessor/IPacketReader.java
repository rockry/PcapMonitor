package packetProcessor;

import jpcap.JpcapCaptor;

public interface IPacketReader {

	/**
	 * Starts process of reading packets.
	 */
	public void startReadingPackets();

	public void stopReadingPackets();

	public JpcapCaptor getCaptor();

	/**
	 * Sets the writer that will be used when a packets is captured. Each
	 * captured packet will be written using the provided writer.
	 * 
	 * @param writer
	 *            writes received packets
	 */
	public void setWriter(IPacketWriter writer);

}
