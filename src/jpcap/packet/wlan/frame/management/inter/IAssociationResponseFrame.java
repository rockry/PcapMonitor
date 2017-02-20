package jpcap.packet.wlan.frame.management.inter;

import java.util.List;

import jpcap.packet.wlan.frame.management.element.IWlanElement;

/**
 * Management frame - Association response frame<br/>
 * <ul>
 * <li>Capability info : 2 Bytes</li>
 * <li>status code : 2 Bytes</li>
 * <li>association id : 2 Bytes</li>
 * <li>tagged parameter : X Bytes</li>
 * </ul>
 * <p>
 * capability info,status code and association id are static information, tagged
 * are dynamic and can be added with respect to their tag element id
 * </p>
 * 
 * @author Bertrand Martel
 * 
 */
public interface IAssociationResponseFrame {

	public byte[] getCapabilityInfo();
	
	public List<IWlanElement> getTaggedParameter();
	
	public int getStatusCode();
	
	public int getAssociationId();
}
