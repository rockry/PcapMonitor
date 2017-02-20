package pcapmonitor;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.TimeZone;

import com.lge.pcapmonitor.R;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import jpcap.packet.Packet;
import jpcap.packet.W80211Packet;
import jpcap.packet.wlan.DisplayDecodingInfo;
import jpcap.packet.wlan.frame.management.inter.*;
import jpcap.packet.wlan.frame.IWlanFrame;
import jpcap.packet.wlan.frame.control.inter.*;
import jpcap.packet.wlan.frame.data.inter.IDataFrame;
import jpcap.packet.wlan.frame.data.inter.INullFrame;
import jpcap.packet.wlan.frame.data.inter.IQosDataFrame;
import jpcap.packet.wlan.inter.IWlan802dot11Radiotap;

class ViewHolder {
    public ImageView mIcon;  
    public TextView mText;   
    public TextView mDate;
}

public class PcapListViewAdapter extends BaseAdapter  {
	private Context mContext = null;
	public ArrayList<Packet> mListData = new ArrayList<Packet>(JpcapTools.LIST_INIT_CAPACITY);
	private boolean mBShowDateTypeHumanType = false;
	private static boolean collapse_view = false;
	private static SharedPreferences preference;
	
	/**
	 * @param mContext
	 */
	public PcapListViewAdapter(Context mContext) {
		super();
		this.mContext = mContext;
		mBShowDateTypeHumanType = false;
		preference = mContext.getSharedPreferences("pcap_setting", Context.MODE_PRIVATE);
		collapse_view = preference.getBoolean("collapse_view",false);

	}

	@Override
	public int getCount() {
		// TODO Auto-generated method stub
		return mListData.size();
	}

	@Override
	public Object getItem(int position) {
		// TODO Auto-generated method stub
		return mListData.get(position);
	}

	@Override
	public long getItemId(int position) {
		// TODO Auto-generated method stub
		return position;
	}

	@Override
	public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder holder;
        if (convertView == null) {
            holder = new ViewHolder();
            
            LayoutInflater inflater = (LayoutInflater) mContext.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.listview_item, null);
            
            holder.mIcon = (ImageView) convertView.findViewById(R.id.mImage);
            holder.mText = (TextView) convertView.findViewById(R.id.mText);
            holder.mDate = (TextView) convertView.findViewById(R.id.mDate);
            
            convertView.setTag(holder);
        }else{
            holder = (ViewHolder) convertView.getTag();
        }
        
        Packet packet = mListData.get(position);

		if (packet.datalink instanceof W80211Packet) {
            int resourceId = getIconResourceId(((IWlan802dot11Radiotap)packet.datalink).getFrame());
            if (resourceId != -1) {
            	holder.mIcon.setVisibility(View.VISIBLE);
            	holder.mIcon.setImageDrawable(mContext.getResources().getDrawable(resourceId, null));
			}else {
	            holder.mIcon.setVisibility(View.GONE);
	        }

			holder.mDate.setText(JpcapTools.getDate(position+1, packet.sec, packet.usec, mBShowDateTypeHumanType));
			if (collapse_view) {
		        holder.mText.setText(DisplayDecodingInfo.getSummaryInfo((IWlan802dot11Radiotap)packet.datalink));
			} else {
		        holder.mText.setText(DisplayDecodingInfo.getMainInfo((IWlan802dot11Radiotap)packet.datalink));				
			}
			//for debug
			//DisplayDecodingInfo.displayAllInfo((IWlan802dot11Radiotap)packet.datalink);
	        
		} else {
			holder.mIcon.setVisibility(View.GONE);
	        holder.mDate.setText(packet.sec+"."+packet.usec);
	        holder.mText.setText(packet.toString());
		}
		
        return convertView;
	}
	
    public void addItem(Packet packet) {
        mListData.add(packet);
    }	

    public void addAllItem(ArrayList<Packet> list) {
        mListData.addAll(list);
    }
    
    public void remove(int position){
        mListData.remove(position);
        dataChange();
    }
    
    public void removeAll(){
        mListData.clear();
        dataChange();
    }
    
    public void sort(){
        // don't use
    }
    
    public void dataChange(){
    	this.notifyDataSetChanged();
    }    

    public void showDateTypeHumanType(boolean type){
    	this.mBShowDateTypeHumanType = type;
    }
    
    private int getIconResourceId(IWlanFrame frame) {
		if (frame instanceof IBeaconFrame) {
            return R.drawable.beacon1;
        } else if (frame instanceof IAssociationRequestFrame) {
            return R.drawable.assocreq;
        } else if (frame instanceof IAssociationResponseFrame) {
            return R.drawable.assocres;
        } else if (frame instanceof IAuthenticationFrame) {
            return R.drawable.auth;
        } else if (frame instanceof IDeauthenticationFrame) {
            return R.drawable.deauth;
        } else if (frame instanceof IDisassociationFrame) {
            return R.drawable.disassoc;
        } else if (frame instanceof IProbeRequestFrame) {
            return R.drawable.probereq;
        } else if (frame instanceof IProbeResponseFrame) {
            return R.drawable.proberes;
        } else if (frame instanceof IReassociationRequestFrame) {
            return R.drawable.reassocreq;
        } else if (frame instanceof IReassociationResponseFrame) {
            return R.drawable.reassocres;
        } else if (frame instanceof IackFrame) {
            return R.drawable.ack;
        } else if (frame instanceof IClearToSendFrame) {
            return R.drawable.cts;
        } else if (frame instanceof IContentionFreeFrame) {
            return R.drawable.cf;
        } else if (frame instanceof IContentionFreeReceiveAckFrame) {
            return R.drawable.cfack;
        } else if (frame instanceof IPowerSavePollingFrame) {
            return R.drawable.pospoll;
        } else if (frame instanceof IRequestToSendFrame) {
            return R.drawable.rts;
        } else if (frame instanceof IDataFrame) {
            return R.drawable.data;
        } else if (frame instanceof INullFrame) {
            return R.drawable.nulldata;
        } else if (frame instanceof IQosDataFrame) {
            return R.drawable.qosdata;
        } else {
        	return -1;
        }
    }
	public static void updateCollapseView() {
		collapse_view = preference.getBoolean("collapse_view",false);
	}
	public static boolean getCollapseView() {
		return collapse_view;
	}
}
