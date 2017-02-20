package jpcap.packet.radiotap;

import android.util.Log;
import pcapmonitor.JpcapTools;

/**
 * Define Modulation and coding scheme extracted from radio tape headers
 * 
 * @author Bertrand Martel
 * 
 */
public class RadioTapMCS {

	/**
	 * define Modulation and coding scheme according to table
	 * 
	 * http://en.wikipedia.org/wiki/IEEE_802.11n-2009#Data_rates
	 */
	private byte mcsRate = 0x00;

	/**
	 * Build a radio tape MCS object
	 * 
	 * @param knownField
	 * @param flagsField
	 * @param mcsField
	 */
	public RadioTapMCS(byte knownField, byte flagsField, byte mcsField) {
		mcsRate = mcsField;
		switch (knownField) {
		case 0x03:
			switch (flagsField) {
			case 0x00:
				Log.d(JpcapTools.TAG, "bandwidth : 20");
			case 0x01:
				Log.d(JpcapTools.TAG, "bandwidth : 40");
			case 0x02:
				Log.d(JpcapTools.TAG, "bandwidth : 20L");
			case 0x03:
				Log.d(JpcapTools.TAG, "bandwidth : 20U");
			}
		case 0x04:
			switch (flagsField) {
			case 0x00:
				Log.d(JpcapTools.TAG, "guard interval : long GI");
			case 0x01:
				Log.d(JpcapTools.TAG, "guard interval : short GI");
			}
		case 0x08:
			switch (flagsField) {
			case 0x00:
				Log.d(JpcapTools.TAG, "HT format : mixed");
			case 0x01:
				Log.d(JpcapTools.TAG, "HT format : greenfield");
			}
		case 0x10:
			switch (flagsField) {
			case 0x00:
				Log.d(JpcapTools.TAG, "FEC type : BCC");
			case 0x01:
				Log.d(JpcapTools.TAG, "FEC type : LDPC");
			}
		case 0x60:
			Log.d(JpcapTools.TAG, "Number of STBC streams : " + (flagsField & 0XFF));
		}
	}

	public byte getMcsRate() {
		return mcsRate;
	}

	public void setMcsRate(byte mcsRate) {
		this.mcsRate = mcsRate;
	}

	public void displayInfo() {
		Log.d(JpcapTools.TAG, "MCS Rate : " + mcsRate);
	}
}
