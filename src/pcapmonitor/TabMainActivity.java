package pcapmonitor;

import com.lge.pcapmonitor.R;

import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.app.TabActivity;
import android.content.Intent;
import android.widget.TabHost;
import android.widget.TabHost.TabSpec;
import utilfile.FileSelector;


@SuppressWarnings("deprecation")
public class TabMainActivity extends TabActivity  {

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.main);

            FileSelector.doCopyDefaultPcapFiles(this);

            // create the TabHost that will contain the Tabs
            TabHost tabHost = (TabHost)findViewById(android.R.id.tabhost);


            TabSpec tab1 = tabHost.newTabSpec("File Tab");
            TabSpec tab2 = tabHost.newTabSpec("Interface Tab");
            TabSpec tab3 = tabHost.newTabSpec("Save File Tab");
            TabSpec tab4 = tabHost.newTabSpec("Graph Tab");
            //TabSpec tab5 = tabHost.newTabSpec("Etc Tab");

           // Set the Tab name and Activity
           // that will be opened when particular Tab will be selected
            tab1.setIndicator(getResources().getString(R.string.tab_file));
            tab1.setContent(new Intent(this,TabActivityFromFile.class));
            
            tab2.setIndicator(getResources().getString(R.string.tab_interface));
            tab2.setContent(new Intent(this,TabActivityFromInterface.class));

            tab3.setIndicator(getResources().getString(R.string.tab_savefile));
            tab3.setContent(new Intent(this,TabActivityFromInterfaceToFile.class));
        
            tab4.setIndicator(getResources().getString(R.string.tab_graph));
            tab4.setContent(new Intent(this,TabActivityFromInterfaceGraph.class));
            
            //tab5.setIndicator(getResources().getString(R.string.tab_etc));
            //tab5.setContent(new Intent(this,Tab3Activity.class));
            
            /** Add the tabs  to the TabHost to display. */
            tabHost.addTab(tab1);
            tabHost.addTab(tab2);
            tabHost.addTab(tab3);
            tabHost.addTab(tab4);
            //tabHost.addTab(tab5);

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
		switch(id){
		case R.id.action_settings :
			Intent intent = new Intent(TabMainActivity.this, AdvancedSetting.class);
			startActivity(intent);
			return true;
		}
		return super.onOptionsItemSelected(item);
	}    
}
