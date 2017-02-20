package packetProcessor;

import java.io.IOException;

import android.util.Log;
import jpcap.JpcapCaptor;
import jpcap.packet.Packet;
import pcapmonitor.JpcapTools;
import utils.StatisticPrinter;

public class FilePacketReader extends AbstractPacketReader {

	private PacketAnalyzer packetAnalyzer;

	public FilePacketReader(String fileName, String packetFilterRule) {
		try {
			JpcapCaptor captor = JpcapCaptor.openFile(fileName);
			if (captor == null) {
				Log.e(JpcapTools.TAG,"FilePacketReader: captor is null");
			}
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
		if (captor != null) {
			Packet packet = null;
			while (true) {
				// read a packet from the opened file
				packet = captor.getPacket();
				// if some error occurred or EOF has reached, break the loop
				if (packet == null || packet == Packet.EOF) {
					break;
				}
				packetAnalyzer.receivePacket(packet);
			}
			// captor.updateStat();
			StatisticPrinter.printStatistics(captor, packetAnalyzer
					.getNetworkSessions(), packetAnalyzer
					.getNumberOfCapturedPackets(), packetAnalyzer
					.getNumberOfModifiedPackets());
			captor.close();
			packetAnalyzer.closeWriter();
		}
	}

	@Override
	public void stopReadingPackets() {
		// do nothing because reading packets from file stops automatically
	}

	@Override
	public void setWriter(IPacketWriter writer) {
		packetAnalyzer.setWriter(writer);
	}

}
