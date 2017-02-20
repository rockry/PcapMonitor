package pcapmonitor;

import com.lge.pcapmonitor.R;

import android.os.Bundle;
import android.os.Handler;
import android.view.Gravity;
import android.app.Activity;
import android.widget.TextView;
import jpcap.packet.Packet;


public class Tab3Activity extends Activity implements IWidgetViewActivity {

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        
        TextView  tv=new TextView(this);
        tv.setTextSize(25);
        tv.setGravity(Gravity.CENTER_VERTICAL);
        tv.setText("This Is Tab3 Activity");
        
        setContentView(tv);
    }

	@Override
	public void setPacket(Packet packet) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void updateView() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void initializeAll() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Handler getHandler() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void initializeInterfaceFunction() {
		// TODO Auto-generated method stub
		
	}

}
