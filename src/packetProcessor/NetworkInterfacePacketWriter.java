package packetProcessor;

import jpcap.JpcapSender;
import jpcap.packet.Packet;

/**
 * This class writes packets through network interfaces
 */
public class NetworkInterfacePacketWriter implements IPacketWriter {

	/**
	 * Network interface packet writer
	 */
	private JpcapSender sender;

	/**
	 * Constructor
	 * 
	 * @param output
	 *            the sender used to send packets througn network interface
	 */
	public NetworkInterfacePacketWriter(JpcapSender output) {
		sender = output;
	}

	/**
	 * Close sending network interface
	 */
	@Override
	public void writePacket(Packet packet) {
		sender.sendPacket(packet);
	}

	@Override
	public void close() {
		sender.close();
	}

}
