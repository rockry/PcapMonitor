package pcapmonitor;

import com.lge.pcapmonitor.R;
import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.TextView;

public class AdvancedSetting extends Activity implements OnCheckedChangeListener {

	CheckBox collapse_check;
	TextView collapse_textview;
	SharedPreferences preference;
	SharedPreferences.Editor sharedP_editor;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);

		setContentView(R.layout.activity_advancedsetting);

		init_settings();
		
	}

	@Override
	public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
		// TODO Auto-generated method stub
		if(buttonView.equals(collapse_check)){
			Log.d("TEST", "onCheckedChanged");
			if(isChecked == true){
				sharedP_editor.putBoolean("collapse_view", true);
			}
			else{
				sharedP_editor.putBoolean("collapse_view", false);
			}
		}
		sharedP_editor.commit();
		PcapListViewAdapter.updateCollapseView();
	}
	
	private void init_settings() {
		preference = getSharedPreferences("pcap_setting", MODE_PRIVATE);
		sharedP_editor = preference.edit();
		
		collapse_check  = (CheckBox)findViewById(R.id.collapse_view);
		collapse_check.setOnCheckedChangeListener(this);
		
		collapse_check.setChecked(preference.getBoolean("collapse_view",false));
		
		collapse_textview = (TextView)findViewById(R.id.collapse_view_text);
		collapse_textview.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				// TODO Auto-generated method stub
				Log.d("TEST", "textview clicked");
				if(collapse_check.isChecked()) {
					collapse_check.setChecked(false);
					sharedP_editor.putBoolean("collapse_view", false);
				}
				else {
					collapse_check.setChecked(true);
					sharedP_editor.putBoolean("collapse_view", true);
				}
				sharedP_editor.commit();
			}
		});
	}

}
