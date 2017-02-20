package pcapmonitor;

import java.util.Arrays;
import java.util.Random;

import android.graphics.Color;
import android.util.Log;
import graph.hzgrapherlib.vo.linegraph.LineGraph;
import jpcap.packet.Packet;
import jpcap.packet.W80211Packet;
import jpcap.packet.wlan.DisplayDecodingInfo;
import jpcap.packet.wlan.frame.IWlanManagementFrame;
import jpcap.packet.wlan.frame.management.inter.IBeaconFrame;
import jpcap.packet.wlan.inter.IWlan802dot11Radiotap;
import jpcap.packet.wlan.utils.ByteUtils;

public class BeaconLineGraph extends LineGraph{

	public static final int DEFAULT_MAX_VALUE = 15;
	public static final int DEFAULT_INCREMENT = 1;
	public static final int DEFAULT_MAX_TIME = 15;
	
	private Random mRandomGenerator = new Random();
	private float[] mBeaconCount = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	
	public static String[] mLegendArr 	= {"1sec","2sec","3sec","4sec","5sec","6sec","7sec","8sec","9sec","10sec","11sec","12sec","13sec","14sec","15sec"};
	private int mCurIndex = 0;
	private int mPreviousNotUpdatedIndex = -1;
	private String mSSID;
	private String mBSSID;
	private String mKey;

	private boolean mIsUpdated = false;
	
	public BeaconLineGraph(String ssid, String bssid) {
		super(ssid+"_"+bssid, 0, null);
		// TODO Auto-generated constructor stub
		setSSID(ssid);
		setBSSID(bssid);
		setKey(ssid, bssid);
		setBeaconCount();
		setRandomColor();
		clearAll();
	}

	public void setPacket(Packet packet) {
		if (packet == null) return;
		
		if (packet.datalink instanceof W80211Packet) {
			if (((IWlan802dot11Radiotap)packet.datalink).getFrame() instanceof IBeaconFrame) {
				
				IWlanManagementFrame managementFrame = (IWlanManagementFrame) ((IWlan802dot11Radiotap)packet.datalink).getFrame();					
				String strBSSID = ByteUtils.byteArrayToStringMessageNoSpace("", managementFrame.getBSSID(), ':');
				
				IBeaconFrame beaconFrame = (IBeaconFrame) managementFrame;			
				String strTimestamp = ByteUtils.byteArrayToStringMessage("", beaconFrame.getTimestamp());		
				String strSSID = DisplayDecodingInfo.getElementTaggedParameterSSID(beaconFrame);
				
				//Log.d(JpcapTools.TAG, strSSID + " " + strBSSID + " " + strTimestamp);
				
				plusBeaconCount(strSSID + "_" + strBSSID, packet.sec);
	        }	        
		} 		
	}
	
	public void plusBeaconCount(String name, long second) {
		if (this.getName().equals(name) == false) {
			return;
		}
		 
		int index = (int)(second % DEFAULT_MAX_TIME);
		
		if (mPreviousNotUpdatedIndex == mCurIndex) {
			mBeaconCount[mCurIndex] = 1;
			mPreviousNotUpdatedIndex = -1;
		}
		
		if (mCurIndex == index) {
			mBeaconCount[mCurIndex] += 1;
		} else {
			mIsUpdated = true;
			mPreviousNotUpdatedIndex = index;
			mCurIndex = index;
			//Log.d(JpcapTools.TAG, this.toString());
		}
	}

	public boolean isUpdated() {
		return mIsUpdated;
	}
	
	public void setUpdated(boolean update) {
		mIsUpdated = update;
	}
	
	public static String[] getmLegendArr() {
		return mLegendArr;
	}
	
	public void clearAll() {
		mCurIndex = 0;
		mPreviousNotUpdatedIndex = -1;
		for (int i = 0; i < mBeaconCount.length - 1; i++) {
			mBeaconCount[i] = 0;
		}
	}

	public String getSSID() {
		return mSSID;
	}

	public void setSSID(String mSSID) {
		this.mSSID = mSSID;
	}

	public String getBSSID() {
		return mBSSID;
	}

	public void setBSSID(String mBSSID) {
		this.mBSSID = mBSSID;
	}

	/**
	 * @return the mBeaconCount
	 */
	public float[] getBeaconCount() {
		return mBeaconCount;
	}

	/**
	 * @param mBeaconCount the mBeaconCount to set
	 */
	public void setBeaconCount() {
		setCoordinateArr(mBeaconCount);
	}

	/**
	 * @return the mCurIndex
	 */
	public int getCurIndex() {
		return mCurIndex;
	}

	/**
	 * @param mCurIndex the mCurIndex to set
	 */
	public void setCurIndex(int mCurIndex) {
		this.mCurIndex = mCurIndex;
	}
	
	public void setRandomColor() {
		this.setColor(Color.rgb(mRandomGenerator.nextInt(256), mRandomGenerator.nextInt(256), mRandomGenerator.nextInt(256)));
	}
	
	/**
	 * @return the mKey
	 */
	public String getKey() {
		return mKey;
	}

	/**
	 * @param mKey the mKey to set
	 */
	public void setKey(String ssid, String bssid) {
		this.mKey = ssid+"_"+bssid;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "BeaconLineGraph [mSSID=" + mSSID + ", mBSSID=" + mBSSID + ", mCurIndex=" + mCurIndex + ", mBeaconCount="
				+ Arrays.toString(mBeaconCount) + "]";
	}
	
}
