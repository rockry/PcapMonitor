package jpcap.packet.wlan.frame.management;

import jpcap.packet.wlan.frame.WlanManagementAbstr;
import jpcap.packet.wlan.frame.management.inter.IDisassociationFrame;
import jpcap.packet.wlan.utils.ByteUtils;

/**
 * Management frame - Disassociation frame<br/>
 * <ul>
 * <li>status code :2 Bytes</li>
 * </ul>
 * <p>
 * contains only fixed parameters
 * </p>
 * 
 * @author Bertrand Martel
 * 
 */
public class DisassociationFrame extends WlanManagementAbstr implements IDisassociationFrame {

	/**
	 * authentication status code
	 */
	private int statusCode = 0;

	/**
	 * Parse Disassociation management frame according to basic management frame
	 * and Disassociation frame specification
	 * 
	 * @param frame
	 *            frame with omitted control frame
	 */
	public DisassociationFrame(byte[] frame) {
		super(frame);
		byte[] frameBody = getFrameBody();
		if (frameBody != null) {
			statusCode = ByteUtils.convertByteArrayToInt(new byte[] {
					frameBody[1], frameBody[0] });
		}
	}

	@Override
	public int getStatusCode() {
		return statusCode;
	}

}
