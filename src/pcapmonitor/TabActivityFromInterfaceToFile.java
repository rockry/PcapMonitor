package pcapmonitor;

import java.io.IOException;
import java.util.ArrayList;
import com.lge.pcapmonitor.R;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.Spinner;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.TextView;
import android.widget.Toast;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import jpcap.packet.W80211Packet;
import jpcap.packet.wlan.DisplayDecodingInfo;
import jpcap.packet.wlan.inter.IWlan802dot11Radiotap;
import utilfile.FileOperation;
import utilfile.FileSelector;
import utilfile.FileUtils;
import utilfile.OnHandleFileListener;


public class TabActivityFromInterfaceToFile extends Activity implements IWidgetViewActivity, OnItemClickListener {

	private static final String[] mFileFilter = { ".pcap"};
	private static final String mPcapSaveFile = FileSelector.mDefaultPcapSaveFolder + FileSelector.mDefaultPcapSaveFile;
    private ListView mListView = null;
    private Button mParsingButton;
    private PcapListViewAdapter mAdapter = null;	
	private ArrayList<Packet> mReceivedPackets = null;
	private int mNumberOfCapturedPackets = 0;	
	private Spinner mFilterSpinner;
	private String mInterfaceName = null;
	private IWidgetViewActivity mIWidgetViewActivity;
	private UpdateHandler mMainHandler = null;
	private MyHander mMyHandler;
	private int mCurrentDeviceIndex;
	private String mSaveFileName = null;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_interfacetofile);
		
		mMainHandler = new UpdateHandler(this);
		mMyHandler = new MyHander(); 
		mIWidgetViewActivity = this;
		
		mReceivedPackets = new ArrayList<Packet>(JpcapTools.LIST_INIT_CAPACITY);
		mNumberOfCapturedPackets = 0;
		mCurrentDeviceIndex = 0;
		
		mListView = (ListView) findViewById(R.id.listViewMain);
        mAdapter = new PcapListViewAdapter(this);
        mAdapter.showDateTypeHumanType(true);
        
        mListView.setAdapter(mAdapter);
        mListView.setOnItemClickListener(this);
        
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
					JpcapTools.ReadPacketFromInterface(devices[mCurrentDeviceIndex], mIWidgetViewActivity, mPcapSaveFile);	
					mParsingButton.setText(R.string.stop);
				} else {
					initializeInterfaceFunction();
					mParsingButton.setText(R.string.capture);
					new FileSelector(TabActivityFromInterfaceToFile.this, FileOperation.SAVE, mLoadFileListener, mFileFilter).show();
				}
				
			}
		});
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
		mReceivedPackets.add(packet);

		mMainHandler.sendUpdateMessage();
	}

	@Override
	public void updateView() {
		// TODO Auto-generated method stub
		mAdapter.removeAll();
		mAdapter.addAllItem(mReceivedPackets);	
		mNumberOfCapturedPackets = mAdapter.getCount();
		
		//Log.d(JpcapTools.TAG, "[updateView] mNumberOfCapturedPackets = " + mNumberOfCapturedPackets + ": mAdapter count = " + mAdapter.getCount());
		
		mAdapter.dataChange();
	}
	
	@Override
	public void initializeAll() {
		// TODO Auto-generated method stub
		initializeInterfaceFunction();
		mParsingButton.setText(R.string.capture);
		mNumberOfCapturedPackets = 0;
		mReceivedPackets.clear();
		mAdapter.removeAll();
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

	@Override
	public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
		// TODO Auto-generated method stub
		Packet packet = (Packet)mAdapter.getItem(position);
		
		// for debug
		if (packet.datalink instanceof W80211Packet) {
			//Log.d("jpcaptest", DisplayDecodingInfo.getAllInfo((IWlan802dot11Radiotap)packet.datalink));
			Toast.makeText(this, DisplayDecodingInfo.getAllInfo((IWlan802dot11Radiotap)packet.datalink), Toast.LENGTH_LONG).show();	
		} else {
			//Log.d("jpcaptest", packet.toString());
			Toast.makeText(this, packet.toString(), Toast.LENGTH_LONG).show();	
		} 			
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
	
	OnHandleFileListener mLoadFileListener = new OnHandleFileListener() {

		@Override
		public void handleFile(final String filePath) {
			try {
				FileUtils.makePcapFile(mPcapSaveFile, filePath);
				Toast.makeText(getApplicationContext(), "Complete to create pcap file.", Toast.LENGTH_LONG).show();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				Toast.makeText(getApplicationContext(), "Sorry! Cannot create pcap file.", Toast.LENGTH_LONG).show();
			} catch (OutOfMemoryError e) {
				Toast.makeText(getApplicationContext(), e.toString(), Toast.LENGTH_LONG).show();
			}
				
		}
	};
}
