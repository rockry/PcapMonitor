package packetProcessor;

import java.net.InetAddress;

import constants.NetworkSessionType;
import constants.PCapFilterConstants;

public class NetworkSession {

	private InetAddress sourceIPAddr;
	private InetAddress destIPAddr;
	private int sourcePort;
	private int destPort;
	private int numberOfPackets;
	private NetworkSessionType type;

	public NetworkSession(InetAddress sourceIPAddr, InetAddress destIPAddr,
			int sourcePort, int destPort) {
		this.sourceIPAddr = sourceIPAddr;
		this.destIPAddr = destIPAddr;
		this.sourcePort = sourcePort;
		this.destPort = destPort;
		initType();
	}

	public void incrementNumberOfPackets() {
		this.numberOfPackets++;
	}

	public int getNumberOfPackets() {
		return this.numberOfPackets;
	}

	public InetAddress getSourceIPAddr() {
		return sourceIPAddr;
	}

	public InetAddress getDestIPAddr() {
		return destIPAddr;
	}

	public int getSourcePort() {
		return sourcePort;
	}

	public int getDestPort() {
		return destPort;
	}

	public NetworkSessionType getType() {
		return type;
	}

	@Override
	public boolean equals(Object otherSession) {
		boolean result = false;
		try {
			if (otherSession != null && otherSession instanceof NetworkSession) {
				NetworkSession networkSession = (NetworkSession) otherSession;
				boolean isIPAddrEquals = ((sourceIPAddr
						.equals(networkSession.sourceIPAddr) && destIPAddr
						.equals(networkSession.destIPAddr)) || (sourceIPAddr
						.equals(networkSession.destIPAddr) && destIPAddr
						.equals(networkSession.sourceIPAddr)));
				boolean isPortEquals = ((sourcePort == networkSession.sourcePort && destPort == networkSession.destPort) || (sourcePort == networkSession.destPort && destPort == networkSession.sourcePort));
				result = isIPAddrEquals && isPortEquals;
			} 
		} catch (NullPointerException e) {
		}
		return result;
	}

	@Override
	public String toString() {
		return "(type=" + type + ", srcIP=" + sourceIPAddr + ", destIP="
				+ destIPAddr + ", srcPort=" + sourcePort + ", destPort="
				+ destPort + ")\npackets in session: " + numberOfPackets;
	}

	private void initType() {
		if (isHTTPSession(sourcePort) || isHTTPSession(destPort)) {
			type = NetworkSessionType.HTTP_SESSION;
		} else if (isSIPSession(sourcePort) || isSIPSession(destPort)) {
			type = NetworkSessionType.SIP_SESSION;
		} else {
			type = NetworkSessionType.OTHER_SESSION;
		}
	}

	private boolean isHTTPSession(int portNumber) {
		return portNumber == PCapFilterConstants.HTTP_TCP_PORT_NUMBER;
	}

	private boolean isSIPSession(int portNumber) {
		return (portNumber >= PCapFilterConstants.SIP_UDP_PORT_NUMBER_MIN && portNumber <= PCapFilterConstants.SIP_UDP_PORT_NUMBER_MAX);
	}

}
