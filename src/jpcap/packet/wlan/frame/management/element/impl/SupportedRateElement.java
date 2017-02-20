package jpcap.packet.wlan.frame.management.element.impl;

import android.util.Log;
import jpcap.packet.wlan.frame.management.element.WlanElementAbstr;
import jpcap.packet.wlan.frame.management.element.inter.ISupportedRateElement;
import pcapmonitor.JpcapTools;

/**
 * Define data rate<br/>
 * <ul>
 * <li>element id : 1 Byte</li>
 * <li>length : 1 Byte</li>
 * <li>data : 1 - 8 Bytes</li>
 * </ul>
 * 
 * @author Bertrand Martel
 * 
 */
public class SupportedRateElement extends WlanElementAbstr implements ISupportedRateElement{

	public final static int id = 1;

	private byte[] dataRate = null;

	public SupportedRateElement(byte[] data) {
		super(data);
		dataRate = data;
	}

	/**
	 * retrieve max rate in Mbps
	 * 
	 * @return
	 */
	public int getMaxRate() {
		if (dataRate.length > 0) {
			Log.d(JpcapTools.TAG, ""+ (dataRate[dataRate.length - 1] & 0x7F) * 500);
			return ((dataRate[dataRate.length - 1] & 0x7F) * 500) / 1000;
		} else {
			return -1;
		}
	}

	@Override
	public byte getElementId() {
		return id;
	}

	@Override
	public byte[] getDataRate() {
		return dataRate;
	}
}
