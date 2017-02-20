package pcapmonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import android.content.Context;
import android.util.Log;
import android.view.ViewGroup;
import graph.hzgrapherlib.graphview.LineGraphView;
import graph.hzgrapherlib.vo.GraphNameBox;
import graph.hzgrapherlib.vo.linegraph.LineGraph;
import graph.hzgrapherlib.vo.linegraph.LineGraphVO;
import jpcap.packet.Packet;
import jpcap.packet.W80211Packet;
import jpcap.packet.wlan.DisplayDecodingInfo;
import jpcap.packet.wlan.frame.IWlanManagementFrame;
import jpcap.packet.wlan.frame.management.inter.IBeaconFrame;
import jpcap.packet.wlan.inter.IWlan802dot11Radiotap;
import jpcap.packet.wlan.utils.ByteUtils;

public class BeaconLineGraphList {
 
	private Context mContext;
	private ViewGroup mLayoutGraphView;
	
	private int paddingBottom 	= LineGraphVO.DEFAULT_PADDING;
	private int paddingTop 		= LineGraphVO.DEFAULT_PADDING;
	private int paddingLeft 	= LineGraphVO.DEFAULT_PADDING;
	private int paddingRight 	= LineGraphVO.DEFAULT_PADDING;

	//graph margin
	private int marginTop 		= LineGraphVO.DEFAULT_MARGIN_TOP;
	private int marginRight 	= LineGraphVO.DEFAULT_MARGIN_RIGHT;

	//max value
	private int maxValue 		= BeaconLineGraph.DEFAULT_MAX_VALUE;

	//increment
	private int increment 		= BeaconLineGraph.DEFAULT_INCREMENT;
	
	private LineGraphView mLineGraphView = null;
	private List<LineGraph> mArrGraph = new ArrayList<LineGraph>();
	private HashMap<String, LineGraph> mBeaconMap = new HashMap<String, LineGraph>();
	
	private int mUpdatedCount;
	
	private List<String> mFilter = new ArrayList<String>();
	/**
	 * 
	 */
	public BeaconLineGraphList(Context context, ViewGroup layoutGraphView) {
		super();
		this.mContext = context;
		this.mLayoutGraphView = layoutGraphView;
	}

	public void setPacket(Packet packet) {		
		if (packet.datalink instanceof W80211Packet) {
			if (((IWlan802dot11Radiotap)packet.datalink).getFrame() instanceof IBeaconFrame) {
				
				IWlanManagementFrame managementFrame = (IWlanManagementFrame) ((IWlan802dot11Radiotap)packet.datalink).getFrame();					
				String strBSSID = ByteUtils.byteArrayToStringMessageNoSpace("", managementFrame.getBSSID(), ':');
				
				IBeaconFrame beaconFrame = (IBeaconFrame) managementFrame;			
				String strSSID = DisplayDecodingInfo.getElementTaggedParameterSSID(beaconFrame);
				
				//Log.d(JpcapTools.TAG, strSSID + " " + strBSSID + " " + strTimestamp);			
				BeaconLineGraph lineGraph = (BeaconLineGraph) mBeaconMap.get(strSSID + "_" + strBSSID);
				if (mBeaconMap.get(strSSID + "_" + strBSSID) != null) {
					lineGraph.setPacket(packet);
				} else {
					mBeaconMap.put(strSSID + "_" + strBSSID, new BeaconLineGraph(strSSID, strBSSID));
				}
	        }	        
		} 
	}
	
	public void clearAll() {
		if (mBeaconMap.size() == 0) return;
		
		for (Entry<String, LineGraph> entry : mBeaconMap.entrySet()) {
		    String key = entry.getKey();
		    BeaconLineGraph lineGraph = (BeaconLineGraph)entry.getValue();
		    Log.d(JpcapTools.TAG, "clear :" + key + " - " + lineGraph.toString());
		    lineGraph.clearAll();
		}	
	}
	
	private boolean isUpdated() {
		boolean bRet = false;
		
		if (mBeaconMap.size() == 0) return false;

		for (Entry<String, LineGraph> entry : mBeaconMap.entrySet()) {
		    //String key = entry.getKey();
		    BeaconLineGraph lineGraph = (BeaconLineGraph)entry.getValue();
			if (lineGraph.isUpdated() == false) {
			} else {
				lineGraph.setUpdated(false);
				mUpdatedCount++;
				//Log.d(JpcapTools.TAG, "mBeaconMap.size()" + mBeaconMap.size() + ", mUpdatedCount = " + mUpdatedCount + " " +lineGraph.toString());
			}
		}	
		
		if (mUpdatedCount >= mBeaconMap.size()){
			mUpdatedCount = 0;
			bRet = true;
			//Log.d(JpcapTools.TAG, "[update == true] mBeaconMap.size()" + mBeaconMap.size() + ", mUpdatedCount = " + mUpdatedCount);
		}
		
		return bRet;
	}
	/**
	 * make line graph using options
	 * @return
	 */
	public void makeLineGraphWithPacket() {	
		
		if (mLayoutGraphView == null) return;
		
		if (isUpdated() == false) return;
		
		//GRAPH SETTING
		mArrGraph.clear();
		for (Entry<String, LineGraph> entry : mBeaconMap.entrySet()) {
		    BeaconLineGraph lineGraph = (BeaconLineGraph)entry.getValue();
		    if (isThisFilterContain(lineGraph) == true) {
		    	mArrGraph.add(lineGraph);
		    	//Log.d(JpcapTools.TAG, lineGraph.toString());
		    }
		}
		
		LineGraphVO vo = new LineGraphVO(
				paddingBottom, paddingTop, paddingLeft, paddingRight,
				marginTop, marginRight, maxValue, increment, BeaconLineGraph.getmLegendArr(), mArrGraph);
		
		//set animation
		//vo.setAnimation(new GraphAnimation(GraphAnimation.LINEAR_ANIMATION, GraphAnimation.DEFAULT_DURATION));
		
		//set graph name box
		vo.setGraphNameBox(new GraphNameBox());
		//set draw graph region

		if (mLineGraphView == null) {
			mLineGraphView = new LineGraphView (mContext, vo);
			mLayoutGraphView.removeAllViews();
			mLayoutGraphView.addView(mLineGraphView);
		} else {
			mLineGraphView.refreshView();
		}
	}
	
	public void addFilter(String ssid_bssid) {
		mFilter.add(ssid_bssid);
	}
	
	public void removeFilter(String ssid_bssid) {
		mFilter.remove(ssid_bssid);
	}

	public void clearAllFilter() {
		mFilter.clear();
	}
	
	private boolean isThisFilterContain(BeaconLineGraph lineGraph) {
		if (mFilter.size() == 0) return true;
		return mFilter.contains(lineGraph.getSSID());
	}
}
