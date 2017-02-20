package packetProcessor;

import jpcap.JpcapWriter;
import jpcap.packet.Packet;
import pcapmonitor.IWidgetViewActivity;

public class WidgetViewWriter implements IPacketWriter {

	/**
	 * File packet writer
	 */
	private JpcapWriter mWriter = null;
	
	private IWidgetViewActivity m_WidgetViewActivity = null;

	public WidgetViewWriter(IWidgetViewActivity output, JpcapWriter outputFile) {
		m_WidgetViewActivity = output;
		mWriter = outputFile;
	}

	@Override
	public void close() {
		if (mWriter != null) {
			mWriter.close();
		}
	}

	@Override
	public void writePacket(Packet packet) {
		if (mWriter != null) {
			mWriter.writePacket(packet);
		} 
	
		if (m_WidgetViewActivity != null) {
			m_WidgetViewActivity.setPacket(packet);
		}
	}

}