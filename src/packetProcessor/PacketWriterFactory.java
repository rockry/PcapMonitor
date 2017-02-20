package packetProcessor;

import java.io.PrintStream;

import jpcap.JpcapSender;
import jpcap.JpcapWriter;
import pcapmonitor.IWidgetViewActivity;

public class PacketWriterFactory {

	public static IPacketWriter getPacketWriter(Object destination, Object destination2) {
		if (destination instanceof JpcapSender) {
			// send packets over the network interface

			JpcapSender sender = (JpcapSender) destination;
			return new NetworkInterfacePacketWriter(sender);
		} else if (destination instanceof JpcapWriter) {
			// write packets to a file

			JpcapWriter writer = (JpcapWriter) destination;
			return new FilePacketWriter(writer);
		} else if (destination instanceof PrintStream) {
			// write packet to the System output

			PrintStream printStream = (PrintStream) destination;
			return new SystemWriter(printStream);
		} else if (destination instanceof IWidgetViewActivity) {
			// write packet to the System output
			
			IWidgetViewActivity widgitViewActivity = (IWidgetViewActivity) destination;
			JpcapWriter writer = null;
			if ((destination2 != null) && (destination2 instanceof JpcapWriter)) {
				writer = (JpcapWriter) destination2;
			}
			return new WidgetViewWriter(widgitViewActivity, writer);
		}

		// if no proper destination objects is provided return null
		return null;
	}

}
