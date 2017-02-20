package jpcap;

import java.util.Arrays;

/**
 * This class represents a network interface.
 * @author kfujii
 */
public class NetworkInterface {
	/** Name of the network interface */
	public String name;
	/** Description about the network interface (e.g., "3Com ..."). May be null.*/
	public String description;
	/** TRUE if this is a loopback interface */
	public boolean loopback;
	/** Name of the datalink of the network interface*/
	public String datalink_name;
	/** Description about the datalink of the network interface. May be null. */
	public String datalink_description;
	/** Ethernet MAC address of the network interface */
	public byte[] mac_address;
	/** Network addresses assigned the network interface. May be null if it is a non-IP (e.g. NetBios) address. */
	public NetworkInterfaceAddress[] addresses;
	
	public NetworkInterface(String name,String description,boolean loopback,
			String datalink_name,String datalink_description,byte[] mac,NetworkInterfaceAddress[] addresses){
		this.name=name;
		this.description=description;
		this.loopback=loopback;
		this.datalink_name=datalink_name;
		this.datalink_description=datalink_description;
		this.mac_address=mac;
		this.addresses=addresses;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "NetworkInterface [name=" + name + ", description=" + description + ", loopback=" + loopback
				+ ", datalink_name=" + datalink_name + ", datalink_description=" + datalink_description
				+ ", mac_address=" + Arrays.toString(mac_address) + ", addresses=" + Arrays.toString(addresses) + "]";
	}
	
}
