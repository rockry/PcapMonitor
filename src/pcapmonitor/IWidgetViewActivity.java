package pcapmonitor;

import android.os.Handler;
import jpcap.packet.Packet;

public interface IWidgetViewActivity {

	public void setPacket(Packet packet);
	public void updateView();
	public void initializeAll();
	public void initializeInterfaceFunction();
	public Handler getHandler();
}
