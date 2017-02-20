package jpcap.packet.wlan.frame.management;

import android.util.Log;
import jpcap.packet.wlan.frame.WlanManagementAbstr;
import jpcap.packet.wlan.frame.management.inter.IAuthenticationFrame;
import jpcap.packet.wlan.utils.ByteUtils;
import pcapmonitor.JpcapTools;

/**
 * Management frame -Authentication frame<br/>
 * <ul>
 * <li>authentication algorithm :2 Bytes</li>
 * <li>authentication sequential number : 2 Bytes</li>
 * <li>status code : 2 Bytes</li>
 * </ul>
 * <p>
 * contains only fixed parameters
 * </p>
 * 
 * @author Bertrand Martel
 * 
 */
public class AuthenticationFrame extends WlanManagementAbstr implements IAuthenticationFrame {

	/**
	 * authentication algorithm
	 */
	private int authenticationAlgorithmNum = 0;

	/**
	 * authentication sequential number
	 */
	private int authenticationSeqNum = 0;

	/**
	 * authentication status code
	 */
	private int statusCode = 0;

	/**
	 * Parse authentication management frame according to basic management frame
	 * and beacon frame specification
	 * 
	 * @param frame
	 *            frame with omitted control frame
	 */
	public AuthenticationFrame(byte[] frame) {
		super(frame);
		byte[] frameBody = getFrameBody();
		if (frameBody == null || frameBody.length < 2) {
			Log.e(JpcapTools.TAG, "error treating Authentication frame[frameBody is null]");
			return;
		}
		authenticationAlgorithmNum = ByteUtils
				.convertByteArrayToInt(new byte[] { frameBody[1], frameBody[0] });
		
		if (frameBody.length <= 2) {
			//Authentication Algorithm: Open System (0)
			Log.e(JpcapTools.TAG, "error treating Authentication frame - Open System ");
			frameBody = null;
			return;
		}
		authenticationSeqNum = ByteUtils
				.convertByteArrayToInt(new byte[] { frameBody[3], frameBody[2] });
		statusCode = ByteUtils.convertByteArrayToInt(new byte[] {
				frameBody[5], frameBody[4] });
	}

	@Override
	public int getAuthenticationAlgorithmNum() {
		return authenticationAlgorithmNum;
	}
	
	@Override
	public int getAuthenticationSeqNum() {
		return authenticationSeqNum;
	}
	
	@Override
	public int getStatusCode() {
		return statusCode;
	}

}
