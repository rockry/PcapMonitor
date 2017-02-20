package jpcap.packet;

import android.util.Log;
import jpcap.packet.radiotap.RadioTap;
import jpcap.packet.radiotap.inter.IRadioTapFrame;
import jpcap.packet.utils.RadioTapException;
import jpcap.packet.wlan.WlanFrameDecoder;
import jpcap.packet.wlan.frame.IWlanFrame;
import jpcap.packet.wlan.inter.IWlan802dot11Radiotap;
import jpcap.packet.wlan.inter.IWlanFrameControl;
import pcapmonitor.JpcapTools;
import jpcap.packet.wlan.DisplayDecodingInfo;

/** This class represents 802.11 packet. */
public class W80211Packet extends DatalinkPacket implements IWlan802dot11Radiotap {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6164113297280610288L;

	/**
	 * 802.11 plus radiotap radio header
	 */	
	private static final int DLT_IEEE802_11_RADIO = 127;
	
	/**
	 * IEEE 802.11 wireless
	 */	
	private static final int DLT_IEEE802_11 = 105;

	/**
	 * radio tap object
	 */
	private IRadioTapFrame radioTap = null;

	/**
	 * wlan frame object
	 */
	private WlanFrameDecoder wlan802dot11 = null;

	private byte[] dataFrame = null;
	
	
	/**
	 * @return the dataFrame
	 */
	public byte[] getDataFrame() {
		return dataFrame;
	}

	/**
	 * 
	 */
	public W80211Packet() {
		this.radioTap = null;
		this.wlan802dot11 = null;
		this.dataFrame = null;
	}

	/**
	 * 
	 */
	public void set80211PacketData(byte[] dataFrame, int linktype) {
		this.dataFrame = dataFrame;
		
		if (linktype == DLT_IEEE802_11_RADIO) {
			// decode radioTap protocol
			radioTapDecode(this.dataFrame);
			// decode wlan protocol
			wlan802dot11Decode(this.dataFrame, getRadioTap().getRadioTapDataLength());
		} else {
			// DLT_IEEE802_11
			// There isn't radiotap in this packet.
			//radioTapDecode();
			// decode wlan protocol
			wlan802dot11Decode(this.dataFrame, 0);
		}
	}
	
	/**
	 * Decode radio tap frames
	 * 
	 * @param frame
	 */
	private void radioTapDecode(byte[] frame) {
		try {
			radioTap = new RadioTap(frame);
		} catch (RadioTapException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Decode wlan 802.11 frames
	 * 
	 * @param frame
	 *            byte aray data frames
	 * @param offset
	 *            offset defined to remove radio tap frames if necessary
	 */
	public void wlan802dot11Decode(byte[] frame, int offset) {
		if ((frame.length - offset) >= 0) {
			byte[] frameWlan = new byte[frame.length - offset];
			System.arraycopy(frame, offset, frameWlan, 0, frame.length - offset);
			wlan802dot11 = new WlanFrameDecoder(frameWlan);
		} else {
			Log.e(JpcapTools.TAG, "An error occured while decoding wlan frame");
		}
	}

	
	@Override
	public IRadioTapFrame getRadioTap() {
		return radioTap;
	}

	@Override
	public IWlanFrameControl getFrameControl() {
		return wlan802dot11.getFrameControl();
	}

	@Override
	public IWlanFrame getFrame() {
		return wlan802dot11.getWlanFrame();
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		// for debug
		//DisplayDecodingInfo.displayAllInfo(this);
		return "W80211Packet [radioTap=" + radioTap + ", wlan802dot11=" + wlan802dot11 + "]";
	}
	

}
