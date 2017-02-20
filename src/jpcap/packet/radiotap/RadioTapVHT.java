package jpcap.packet.radiotap;

import android.util.Log;
import pcapmonitor.JpcapTools;

/**
 * Define Very High ThroughPut radio header type
 * 
 * @author Bertrand Martel
 * 
 */
public class RadioTapVHT {

	public RadioTapVHT(byte[] known, byte flags, byte bandwith, byte mcs_nss,
			byte coding, byte groupId, byte[] partialAid) {
		Log.d(JpcapTools.TAG, "Very High ThroughPut detected... Not treating...");
	}
}
