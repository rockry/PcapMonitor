package packetProcessor;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import android.util.Log;
import utils.ConfigurationReader;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import manipulator.PacketManipulator;
import pcapmonitor.JpcapTools;
import constants.PCapFilterConstants;

public class PacketAnalyzer implements PacketReceiver {

	private List<Packet> receivedPackets;
	private List<NetworkSession> networkSessions;
	private int numberOfCapturedPackets;
	private int numberOfModifiedPackets;
	private PacketManipulator packetManipulator;

	/**
	 * Used to write every received packet.
	 */
	private IPacketWriter writer;

	public PacketAnalyzer() {
		this.receivedPackets = new ArrayList<Packet>(JpcapTools.LIST_INIT_CAPACITY);
		this.networkSessions = new ArrayList<NetworkSession>();
	}

	public PacketAnalyzer(String filterRule) {
		this();
		initPacketManipulator(filterRule);
	}

	public List<Packet> getReceivedPackets() {
		return receivedPackets;
	}

	public int getNumberOfCapturedPackets() {
		return numberOfCapturedPackets;
	}

	public int getNumberOfModifiedPackets() {
		return numberOfModifiedPackets;
	}

	@Override
	public void receivePacket(Packet packet) {
		numberOfCapturedPackets++;
		// analyze packet
		handleTransportPacket(packet);
		writer.writePacket(packet); // write packet
		this.receivedPackets.add(packet);

	}

	public List<NetworkSession> getNetworkSessions() {
		return networkSessions;
	}

	/**
	 * Sets the writer used to send packets.
	 * 
	 * @param packetWriter
	 *            sends packet to a predefined destination
	 */
	public void setWriter(IPacketWriter packetWriter) {
		this.writer = packetWriter;
	}

	public IPacketWriter getWriter() {
		return this.writer;
	}
	
	/**
	 * Closes the current writer
	 */
	public void closeWriter() {
		this.writer.close();
	}

	private void initPacketManipulator(String filterRule) {
		String propFileName = getPropFileNameByFilterRule(filterRule);
		if (propFileName != null) {
			Properties prop = new Properties();
			try {
				prop.load(new FileInputStream(propFileName));
				packetManipulator = new PacketManipulator(prop);
			} catch (FileNotFoundException e) {
				Log.e(JpcapTools.TAG, "PacketAnalyzer: Properties file '"
						+ propFileName + "' is not found.");
			} catch (IOException e) {
				Log.e(JpcapTools.TAG, "PacketAnalyzer: Properties file '"
						+ propFileName + "' cannot be loaded.");
			}
		}
	}

	private String getPropFileNameByFilterRule(String filterRule) {
		String propFileName = null;
		if (filterRule != null) {
			boolean filterContainsMinSIPPort = filterRule.contains(String
					.valueOf(PCapFilterConstants.SIP_UDP_PORT_NUMBER_MIN));
			boolean filterContainsMaxSIPPort = filterRule.contains(String
					.valueOf(PCapFilterConstants.SIP_UDP_PORT_NUMBER_MAX));
			boolean filterContainsHTTPPort = filterRule.contains(String
					.valueOf(PCapFilterConstants.HTTP_TCP_PORT_NUMBER));
			if (filterContainsMinSIPPort || filterContainsMaxSIPPort) {
				propFileName = ConfigurationReader
						.getValue(PCapFilterConstants.SIP_MASK_FILE_CONFIG_KEY);
			} else if (filterContainsHTTPPort) {
				propFileName = ConfigurationReader
						.getValue(PCapFilterConstants.HTTP_MASK_FILE_CONFIG_KEY);
			}
		}
		return propFileName;
	}

	private void handleTransportPacket(Packet packet) {
		if (packet != Packet.EOF) {
			InetAddress sourceIPAddr = null;
			InetAddress destIPAddr = null;
			int sourcePort = PCapFilterConstants.INVALID_PORT_NUMBER;
			int destPort = PCapFilterConstants.INVALID_PORT_NUMBER;
			boolean transportPacketCaptured = false;
			if (packet instanceof UDPPacket) {
				UDPPacket udpPacket = (UDPPacket) packet;
				sourceIPAddr = udpPacket.src_ip;
				destIPAddr = udpPacket.dst_ip;
				sourcePort = udpPacket.src_port;
				destPort = udpPacket.dst_port;
				transportPacketCaptured = true;
			} else if (packet instanceof TCPPacket) {
				TCPPacket tcpPacket = (TCPPacket) packet;
				sourceIPAddr = tcpPacket.src_ip;
				destIPAddr = tcpPacket.dst_ip;
				sourcePort = tcpPacket.src_port;
				destPort = tcpPacket.dst_port;
				transportPacketCaptured = true;
			}
			if (transportPacketCaptured == true) {
				isNetworkSessionExists(sourceIPAddr, destIPAddr, sourcePort,
						destPort);
				if (packetManipulator != null) {
					byte[] currentPacketData = packet.data;
					byte[] newPacketData = packetManipulator
							.modifyPacket(currentPacketData);
					if (Arrays.equals(currentPacketData, newPacketData) == false) {
						packet.data = newPacketData;
						numberOfModifiedPackets++;
					}
				}
			}
		}
	}

	/**
	 * Check if there is new network session and adds it to the pool of
	 * sessions.
	 * 
	 * @param sourceIPAddr
	 * @param destIPAddr
	 * @param sourcePort
	 * @param destPort
	 * @return
	 */
	private boolean isNetworkSessionExists(InetAddress sourceIPAddr,
			InetAddress destIPAddr, int sourcePort, int destPort) {
		NetworkSession otherSession = new NetworkSession(sourceIPAddr,
				destIPAddr, sourcePort, destPort);
		if (networkSessions.size() > 0) {
			for (NetworkSession session : networkSessions) {
				if (otherSession.equals(session)) {
					session.incrementNumberOfPackets();
					return true;
				}
			}
		}
		networkSessions.add(otherSession);
		otherSession.incrementNumberOfPackets();
		return false;
	}
}
