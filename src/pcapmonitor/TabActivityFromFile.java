package pcapmonitor;

import java.util.ArrayList;
import com.lge.pcapmonitor.R;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import jpcap.packet.Packet;
import jpcap.packet.W80211Packet;
import jpcap.packet.wlan.DisplayDecodingInfo;
import jpcap.packet.wlan.inter.IWlan802dot11Radiotap;
import utilfile.FileOperation;
import utilfile.FileSelector;
import utilfile.OnHandleFileListener;

public class TabActivityFromFile extends Activity implements IWidgetViewActivity, OnItemClickListener  {

	private static final String[] mFileFilter = { ".pcap", "*.*"};
	
	private Button mLoadButton;
	private Button mParsingButton;
    private ListView mListView = null;
    private TextView mDetailedText = null;
    private PcapListViewAdapter mAdapter = null;	
	private ArrayList<Packet> mReceivedPackets = null;
	private int mNumberOfCapturedPackets = 0;
	private EditText mEditText;
	private IWidgetViewActivity mIWidgetViewActivity;
	private String mCurrentFileName = null;
	private UpdateHandler mMainHandler = null;
	 
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_file_collapse);
		
		mMainHandler = new UpdateHandler(this);
		 
		mIWidgetViewActivity = this;
		mReceivedPackets = new ArrayList<Packet>(JpcapTools.LIST_INIT_CAPACITY);
		mNumberOfCapturedPackets = 0;
		
		mListView = (ListView) findViewById(R.id.listViewMain);
        mAdapter = new PcapListViewAdapter(this);
        mAdapter.showDateTypeHumanType(true);

        mListView.setAdapter(mAdapter);
        mListView.setOnItemClickListener(this);
        
        mDetailedText = (TextView) findViewById(R.id.detailed_text);
        mDetailedText.canScrollVertically(1);
//        mDetailedTextLayout = (LinearLayout) findViewById(R.id.detailed_text_layout);
        updateCollapse();
        
        mLoadButton = (Button) findViewById(R.id.buttonloadfile);
		mLoadButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(final View v) {
				new FileSelector(TabActivityFromFile.this, FileOperation.LOAD, mLoadFileListener, mFileFilter).show();
			}
		});
		
		mParsingButton = (Button) findViewById(R.id.buttonParsing);
		mParsingButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(final View v) {
				if (mCurrentFileName == null || mCurrentFileName.isEmpty()) {
					Toast.makeText(getApplicationContext(), "Select file!!!!!", Toast.LENGTH_LONG).show();	
					return;
				}
				
				initializeAll();
				JpcapTools.ReadPacketFromFile(mCurrentFileName, mIWidgetViewActivity);	
			}
		});
		
		mEditText = (EditText) findViewById(com.lge.pcapmonitor.R.id.textviewfile);
		mEditText.setFocusable(false);
		
	}

	private void updateCollapse() {
		if(PcapListViewAdapter.getCollapseView()) {
			mDetailedText.setLayoutParams(
					new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT));
		} else {
			mDetailedText.setText("");
			mDetailedText.setLayoutParams(
					new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
		}
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
		
		initializeInterfaceFunction();
		// TODO Auto-generated method stub
		super.onPause();
	}
	@Override
	protected void onResume() {
		
		updateCollapse();
		super.onResume();
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
		if(PcapListViewAdapter.getCollapseView()) {
			if (packet.datalink instanceof W80211Packet) {
				mDetailedText.setText(DisplayDecodingInfo.getAllInfo((IWlan802dot11Radiotap)packet.datalink));
			} else {
				mDetailedText.setText(packet.toString());
			}
		} else {
			if (packet.datalink instanceof W80211Packet) {
				//Log.d("jpcaptest", DisplayDecodingInfo.getAllInfo((IWlan802dot11Radiotap)packet.datalink));
				Toast.makeText(this, DisplayDecodingInfo.getAllInfo((IWlan802dot11Radiotap)packet.datalink), Toast.LENGTH_LONG).show();	
			} else {
				//Log.d("jpcaptest", packet.toString());
				Toast.makeText(this, packet.toString(), Toast.LENGTH_LONG).show();
			}
		}
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
	
	OnHandleFileListener mLoadFileListener = new OnHandleFileListener() {
		@Override
		public void handleFile(final String filePath) {
			
			String[] strFilePaths = filePath.split("/");
			if (strFilePaths.length >= 3) {
				mEditText.setText(strFilePaths[strFilePaths.length-2] + "/" + strFilePaths[strFilePaths.length-1]);
			} else {
				mEditText.setText(filePath);
			}
			
			//mTextView.setText(filePath);
			mCurrentFileName = filePath;
			// for debug
			//Toast.makeText(getApplicationContext(), "Load: " + filePath, Toast.LENGTH_SHORT).show();
		}
	};
}
