package jpcap.packet.wlan.frame.management;

import jpcap.packet.wlan.frame.WlanManagementAbstr;
import jpcap.packet.wlan.frame.management.inter.IibssAnnoucementIndicationMapFrame;

/**
 * Management frame for IBSS Annoucement indication map
 * 
 * @author Bertrand Martel
 * 
 */
public class IbssAnnouncementIndicationMapFrame extends WlanManagementAbstr implements IibssAnnoucementIndicationMapFrame {

	/**
	 * Parse IBSS announcement indication map
	 * 
	 * @param frame
	 *            frame with omitted control frame
	 */
	public IbssAnnouncementIndicationMapFrame(byte[] frame) {
		super(frame);
	}
}
