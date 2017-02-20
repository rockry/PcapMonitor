package packetProcessor;

import jpcap.packet.Packet;

public interface IPacketWriter {

	public void writePacket(Packet packet);
	
	public void close();
	
}
