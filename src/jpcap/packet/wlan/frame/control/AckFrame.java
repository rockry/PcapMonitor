package jpcap.packet.wlan.frame.control;

import android.util.Log;
import jpcap.packet.wlan.frame.IWlanFrame;
import jpcap.packet.wlan.frame.control.inter.IackFrame;
import jpcap.packet.wlan.inter.IWlanControlFrame;
import pcapmonitor.JpcapTools;

/**
 * Control frame - ACK <br/>
 * <ul>
 * <li>duration id : 2 Bytes</li>
 * <li>receiver address : 6 Bytes</li>
 * </ul>
 * 
 * @author Bertrand Martel
 * 
 */
public class AckFrame implements IWlanFrame,IWlanControlFrame,IackFrame {

	/**
	 * duration id
	 */
	private byte[] durationId = null;

	/**
	 * receiver addresss
	 */
	private byte[] receiverAddr = null;

	/**
	 * Build control frame ACK
	 * 
	 * @param frame
	 *            wlan frame with control frame omitted
	 */
	public AckFrame(byte[] frame) {
		if (frame.length >= 8) {
			durationId = new byte[] { frame[0], frame[1] };
			receiverAddr = new byte[] { frame[2], frame[3], frame[4], frame[5],
					frame[6], frame[7] };
		} else {
			Log.e(JpcapTools.TAG, "error treating Control frame - clear to send frame");
		}
	}

	@Override
	public byte[] getDurationId() {
		return durationId;
	}
	@Override
	public byte[] getReceiverAddr() {
		return receiverAddr;
	}


}
