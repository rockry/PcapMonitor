package pcapmonitor;

import android.os.Handler;
import android.os.Message;

public class UpdateHandler extends Handler{
	
	public static final int SEND_UPDATE_VIEW = 1;
	
	private IWidgetViewActivity mIWidgetViewActivity;
	
	/**
	 * @param mIWidgetViewActivity
	 */
	public UpdateHandler(IWidgetViewActivity mIWidgetViewActivity) {
		super();
		this.mIWidgetViewActivity = mIWidgetViewActivity;
	}

	/* (non-Javadoc)
	 * @see android.os.Handler#handleMessage(android.os.Message)
	 */
	@Override
	public void handleMessage(Message msg) {
		// TODO Auto-generated method stub
		//super.handleMessage(msg);
		
		switch (msg.what) {
		case SEND_UPDATE_VIEW :
			mIWidgetViewActivity.updateView();
			break;
		default :
			break;
		}
	}
	
	public void sendUpdateMessage() {
		if (this.hasMessages(SEND_UPDATE_VIEW) == true) {
			return;
		}
		
		sendEmptyMessage(SEND_UPDATE_VIEW);
	}
	
	public void sendUpdateMessageDelayed(int millisecond) {
		if (this.hasMessages(SEND_UPDATE_VIEW) == true) {
			return;
		}
		
		this.sendEmptyMessageDelayed(SEND_UPDATE_VIEW, millisecond);
		
	}
}
