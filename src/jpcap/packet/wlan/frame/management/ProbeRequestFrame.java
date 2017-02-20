package jpcap.packet.wlan.frame.management;

import java.util.List;

import jpcap.packet.wlan.frame.WlanManagementAbstr;
import jpcap.packet.wlan.frame.management.element.IWlanElement;
import jpcap.packet.wlan.frame.management.element.WlanElementIdDecoder;
import jpcap.packet.wlan.frame.management.inter.IProbeRequestFrame;

/**
 * Probe request management frame decoder<br/>
 * <ul>
 * <li>tagged parameters : X bytes</li>
 * </ul>
 * 
 * @author Bertrand Martel
 * 
 */
public class ProbeRequestFrame extends WlanManagementAbstr implements IProbeRequestFrame{

	private List<IWlanElement> taggedParameter = null;

	public ProbeRequestFrame(byte[] frame) {
		super(frame);
		WlanElementIdDecoder decoder = new WlanElementIdDecoder();
		taggedParameter = decoder.decode(getFrameBody());

	}

	@Override
	public List<IWlanElement> getTaggedParameter() {
		return taggedParameter;
	}
}
