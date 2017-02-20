package packetProcessor;

import utils.ConfigurationReader;
import constants.PCapFilterConstants;
import jpcap.NetworkInterface;

/**
 * This factory class provides instances for reading packets.
 */
public class PacketReaderFactory {

	/**
	 * Provides an <code>IPacketReader</code> instance for reading packets from
	 * the specified source.
	 * 
	 * @param source
	 *            determined the source where packets will be read from.
	 * @return <code>IPacketReader</code> for reading packets
	 */
	public static IPacketReader getPacketReader(Object source) {
		String filterRule = ConfigurationReader
				.getValue(PCapFilterConstants.FILTER_CONFIG_KEY);
		if (source instanceof String) {
			String fileName = (String) source;
			FilePacketReader filePacketReader = new FilePacketReader(fileName,
					filterRule);
			return filePacketReader;

		} else if (source instanceof NetworkInterface) {
			NetworkInterface networkInterface = (NetworkInterface) source;
			NetworkInterfacePacketReader networkInterfacePacketReader = new NetworkInterfacePacketReader(
					networkInterface, filterRule);
			return networkInterfacePacketReader;
		}
		return null;
	}

}
