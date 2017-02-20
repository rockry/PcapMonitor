package packetProcessor;

import java.io.IOException;

import jpcap.JpcapCaptor;

/**
 * Represents common method implementations.
 *
 */
public abstract class AbstractPacketReader implements IPacketReader, Runnable {

	private String packetFilterRule;

	private JpcapCaptor captor;

	@Override
	public JpcapCaptor getCaptor() {
		return this.captor;
	}

	public void setCaptor(JpcapCaptor captor) {
		this.captor = captor;
	}

	public String getPacketFilterRule() {
		return packetFilterRule;
	}

	public void setPacketFilterRule(String packetFilterRule) {
		if (packetFilterRule != null) {
			this.packetFilterRule = packetFilterRule;
			try {
				this.captor.setFilter(packetFilterRule, true);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	@Override
	public void startReadingPackets() {
		Thread thread = new Thread(this);
		thread.start();
		Thread.yield();
	}
}
