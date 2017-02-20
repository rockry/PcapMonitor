package packetProcessor;

import java.io.IOException;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import utils.StatisticPrinter;

public class NetworkInterfacePacketReader extends AbstractPacketReader {

	private PacketAnalyzer packetAnalyzer;

	public NetworkInterfacePacketReader(NetworkInterface networkInterface,
			String packetFilterRule) {
		try {
			JpcapCaptor captor = JpcapCaptor.openDevice(networkInterface,
					65535, true, 0);
			setCaptor(captor);
			if (packetFilterRule != null) {
				setPacketFilterRule(packetFilterRule);
				this.packetAnalyzer = new PacketAnalyzer(packetFilterRule);
			} else {
				this.packetAnalyzer = new PacketAnalyzer();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		JpcapCaptor captor = getCaptor();
		captor.setNonBlockingMode(true);
		captor.loopPacket(-1, packetAnalyzer);
		captor.updateStat();
		StatisticPrinter.printStatistics(captor, packetAnalyzer.getNetworkSessions(),
				packetAnalyzer.getNumberOfCapturedPackets(), packetAnalyzer.getNumberOfModifiedPackets());
	}

	@Override
	public void stopReadingPackets() {
		JpcapCaptor captor = getCaptor();
		captor.breakLoop();
		captor.close();

		packetAnalyzer.closeWriter();
	}

	@Override
	public void setWriter(IPacketWriter writer) {
		packetAnalyzer.setWriter(writer);
	}
}
