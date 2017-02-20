package jpcap.packet.wlan.frame.management.inter;

import java.util.List;

import jpcap.packet.wlan.frame.management.element.IWlanElement;

/**
 * Probe response management frame decoder<br/>
 * <ul>
 * <li>timestamp : 8 Bytes</li>
 * <li>beacon interval : 2 Bytes</li>
 * <li>capability information : 2 Bytes</li>
 * <li>tagged parameters : X bytes</li>
 * </ul>
 * 
 * @author Bertrand Martel
 * 
 */
public interface IProbeResponseFrame {

	public List<IWlanElement> getTaggedParameter();
	
	public byte[] getTimestamp();
	
	public byte[] getBeaconInterval();
	
	public byte[] getCapabilityInformation();
}
