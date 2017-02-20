package manipulator;

import java.util.Properties;

/**
 * This class is responsible for manipulating packets. The headers that need to
 * be manipulated are defined in the properties file that goes in the
 * constructor.
 */
public class PacketManipulator {

	/**
	 * String separating the header from its value.
	 */
	private static final String HEADER_VALUE_SEPARATOR = ":";

	/**
	 * Properties file that defines the rules that packets are modified
	 */
	private Properties rules;

	/**
	 * Constructor
	 * 
	 * @param prop
	 *            properties file defining the rules for manipulating packets
	 */
	public PacketManipulator(Properties prop) {
		rules = prop;
	}

	/**
	 * Modify the provided packet
	 * 
	 * @param packet
	 *            packet that need to be modified
	 * @return the modified packet. Modification is based on the properties file
	 *         that the class was initialized with
	 */
	public byte[] modifyPacket(byte[] packet) {
		String applicationPacketString = new String(packet);
		String[] sipElements = applicationPacketString.split("\\n");

		for (int i = 0; i < sipElements.length; i++) {
			for (Object key : rules.keySet()) {
				String headerName = (String) key;

				if (sipElements[i].startsWith(headerName)) {
					String newHeaderData = rules.getProperty(headerName);
					sipElements[i] = rewriteElement(headerName, newHeaderData);
				}
			}
		}

		StringBuilder newAppPacketSb = new StringBuilder();
		for (int i = 0; i < sipElements.length - 1; i++) {
			newAppPacketSb.append(sipElements[i]);
			newAppPacketSb.append("\n");
		}
		// omit the new line to keen the initial format
		newAppPacketSb.append(sipElements[sipElements.length - 1]);
		return newAppPacketSb.toString().getBytes();
	}

	private String rewriteElement(String headerName, String newValue) {
		String newElement = new String();
		newElement += headerName;
		newElement += HEADER_VALUE_SEPARATOR;
		newElement += " ";
		newElement += newValue;

		return newElement;
	}
}
