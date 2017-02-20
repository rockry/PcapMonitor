package jpcap.packet.wlan.frame.management;

import android.util.Log;
import jpcap.packet.wlan.frame.WlanManagementAbstr;
import jpcap.packet.wlan.frame.management.inter.IDeauthenticationFrame;
import jpcap.packet.wlan.utils.ByteUtils;
import pcapmonitor.JpcapTools;

/**
 * Management frame - DeAuthentication frame<br/>
 * <ul>
 * <li>reason code :2 Bytes</li>
 * </ul>
 * <p>
 * contains only fixed parameters
 * </p>
 * 
 * @author Bertrand Martel
 * 
 */
public class DeAuthenticationFrame extends WlanManagementAbstr implements IDeauthenticationFrame{

	/**
	 * authentication reason code
	 */
	private int reasonCode = 0;

	/**
	 * Parse DeAuthentication management frame according to basic management
	 * frame and beacon frame specification
	 * 
	 * @param frame
	 *            frame with omitted control frame
	 */
	public DeAuthenticationFrame(byte[] frame) {
		super(frame);
		byte[] frameBody = getFrameBody();
		if (frameBody == null) {
			Log.e(JpcapTools.TAG, "error treating DeAuthentication frame - frameBody is null");
			return;
		}
		reasonCode = ByteUtils.convertByteArrayToInt(new byte[] {
				frameBody[1], frameBody[0] });
	}

	@Override
	public int getReasonCode() {
		return reasonCode;
	}
}
