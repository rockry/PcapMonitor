package jpcap.packet.wlan.inter;

import jpcap.packet.radiotap.inter.IRadioTapFrame;
import jpcap.packet.wlan.frame.IWlanFrame;

/**
 *
 * Template for Wlan 802.11 frame with preceding radiotap header
 * 
 * @author Bertrand Martel
 *
 */
public interface IWlan802dot11Radiotap {

	public IRadioTapFrame getRadioTap() ;
	
	public IWlanFrameControl getFrameControl();
	
	public IWlanFrame getFrame();
}
