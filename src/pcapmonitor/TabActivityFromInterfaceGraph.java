package pcapmonitor;

import java.util.ArrayList;

import com.lge.pcapmonitor.R;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.TextView;
import android.widget.Toast;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import jpcap.packet.W80211Packet;
import jpcap.packet.wlan.frame.management.inter.IBeaconFrame;
import jpcap.packet.wlan.inter.IWlan802dot11Radiotap;
import graph.hzgrapherlib.graphview.LineGraphView;

public class TabActivityFromInterfaceGraph extends Activity implements IWidgetViewActivity {

	private ViewGroup layoutGraphView;
	
    private Button mParsingButton;
	//private ArrayList<Packet> mReceivedPackets = null;
	//private ArrayList<Packet> mReceivedPacketsForBeacon = null;
	private int mNumberOfCapturedPackets = 0;	
	private Spinner mFilterSpinner;
	private String mInterfaceName = null;
	private IWidgetViewActivity mIWidgetViewActivity;
	private UpdateHandler mMainHandler = null;
	private MyHander mMyHandler;
	private int mCurrentDeviceIndex;
	private int mCurrentDisplayPos;
	
	private BeaconLineGraphList mBeaconLineGraphList = null;
	
	private LineGraphView mLineGraphView = null;
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_graph);
		
		layoutGraphView = (ViewGroup) findViewById(R.id.layoutGraphView);
		
		mMainHandler = new UpdateHandler(this);
		mMyHandler = new MyHander(); 
		mIWidgetViewActivity = this;
		
		//mReceivedPackets = new ArrayList<Packet>(JpcapTools.LIST_INIT_CAPACITY);
		//mReceivedPacketsForBeacon = new ArrayList<Packet>(JpcapTools.LIST_INIT_CAPACITY);
		mNumberOfCapturedPackets = 0;
		mCurrentDeviceIndex = 0;
		
        
        mParsingButton = (Button) findViewById(R.id.buttonParsing);
		mParsingButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(final View v) {
				String strButton = mParsingButton.getText().toString();
				if (strButton.equalsIgnoreCase(getResources().getString(R.string.capture))) {
					if (mInterfaceName == null || mInterfaceName.isEmpty()) {
						Toast.makeText(getApplicationContext(), "Select Interface!!!!!", Toast.LENGTH_LONG).show();	
						return;
					}
					
					NetworkInterface[] devices = JpcapTools.getNetworkInterface();
					if ((devices == null) || (devices.length == 0) || (mCurrentDeviceIndex >= devices.length)) {
						Toast.makeText(getApplicationContext(), "Not found Interface. Check your devie permission.", Toast.LENGTH_LONG).show();	
						return;
					}
					initializeAll();
					JpcapTools.ReadPacketFromInterface(devices[mCurrentDeviceIndex], mIWidgetViewActivity, null);	
					mParsingButton.setText(R.string.stop);
				} else {
					initializeInterfaceFunction();
					mParsingButton.setText(R.string.capture);
				}
				
			}
		});
		
		mBeaconLineGraphList = new BeaconLineGraphList(this.getApplicationContext(), layoutGraphView);
		//mBeaconLineGraphList.addFilter("FREE_U+zone");
		//mBeaconLineGraphList.addFilter("5G_T wifi zone_secure");
		//mBeaconLineGraphList.addFilter("LGR200_C8C8C8.OSC");
	}
	
	/**
	 * make line graph using options
	 * @return
	 */
	private void makeGraph() {	
		if (mBeaconLineGraphList == null) {
			return;
		} 
		
		mBeaconLineGraphList.makeLineGraphWithPacket();
	}
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	/* (non-Javadoc)
	 * @see android.app.Activity#onPause()
	 */
	@Override
	protected void onPause() {
		// TODO Auto-generated method stub
		super.onPause();
		initializeInterfaceFunction();
		mParsingButton.setText(R.string.capture);
	}

	/* (non-Javadoc)
	 * @see android.app.Activity#onResume()
	 */
	@Override
	protected void onResume() {
		// TODO Auto-generated method stub
		super.onResume();
		mMyHandler.sendEmptyMessage(0);
	}

	@Override
	public void setPacket(Packet packet) {
		
		if (mNumberOfCapturedPackets >= Integer.MAX_VALUE) {
			Log.e(JpcapTools.TAG, "ERROR: mNumberOfCapturedPackets = " + mNumberOfCapturedPackets + "- Exceed Integer.MAX_VALUE " + Integer.MAX_VALUE);
			return;
		}
		
		//store packet in this class
		//mReceivedPackets.add(packet);
		if (packet.datalink instanceof W80211Packet) {
			if (((IWlan802dot11Radiotap)packet.datalink).getFrame() instanceof IBeaconFrame) {
				//mReceivedPacketsForBeacon.add(packet);
				mBeaconLineGraphList.setPacket(packet);
				mMainHandler.sendUpdateMessage();
	        }	        
		} 
	}

	@Override
	public void updateView() {
		// TODO Auto-generated method stub
		makeGraph();
	}
	
	@Override
	public void initializeAll() {
		// TODO Auto-generated method stub
		initializeInterfaceFunction();
		mParsingButton.setText(R.string.capture);
		mNumberOfCapturedPackets = 0;
		//mReceivedPackets.clear();
		//mReceivedPacketsForBeacon.clear();
		
		if (mBeaconLineGraphList != null) {
			mBeaconLineGraphList.clearAll();
		}
	}
	
	@Override
	public void initializeInterfaceFunction() {
		// TODO Auto-generated method stub
		JpcapTools.StopReadPacketFromInterface();
	}
	
	@Override
	public Handler getHandler() {
		// TODO Auto-generated method stub
		return mMainHandler;
	}


	private void prepareFilterSpinner(String[] interfacelists) {
		mFilterSpinner = (Spinner) findViewById(R.id.fileFilter);
		if (interfacelists == null || interfacelists.length == 0) {
			interfacelists = new String[] { "Not found Iface. Check Permission" };
			mFilterSpinner.setEnabled(false);
		} else {
			mFilterSpinner.setEnabled(true);
		}
		
		ArrayAdapter<String> adapter = new ArrayAdapter<String>(this, R.layout.spinner_item, interfacelists);

		mFilterSpinner.setAdapter(adapter);
		OnItemSelectedListener onItemSelectedListener = new OnItemSelectedListener() {

			@Override
			public void onItemSelected(AdapterView<?> aAdapter, View aView, int arg2, long arg3) {
				TextView textViewItem = (TextView) aView;
				String strTemp = textViewItem.getText().toString();
				if(strTemp.isEmpty() || (strTemp.indexOf(':') == -1) || (strTemp.indexOf('(') == -1)) {
					mInterfaceName = "";
				} else {
					mInterfaceName = strTemp.substring(strTemp.indexOf(':')+1, strTemp.indexOf('('));
					mCurrentDeviceIndex = arg2;
				}
			}

			@Override
			public void onNothingSelected(AdapterView<?> arg0) {

			}
		};
		mFilterSpinner.setOnItemSelectedListener(onItemSelectedListener);
	}

	/* (non-Javadoc)
	 * @see android.app.Activity#onBackPressed()
	 */
	@Override
	public void onBackPressed() {
		// TODO Auto-generated method stub
		initializeAll();
		super.onBackPressed();
	}

	class MyHander extends Handler {
		@Override
		public void handleMessage(Message msg) {
			// TODO Auto-generated method stub
			//super.handleMessage(msg);
			
			switch (msg.what) {
			default :
				prepareFilterSpinner(JpcapTools.ReadInterfaceEx());
				break;
			}
		}		
	}
}
