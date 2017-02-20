package utilfile;

import com.lge.pcapmonitor.R;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Environment;
import android.view.Gravity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Create the file selection dialog. This class will create a custom dialog for
 * file selection which can be used to save files.
 */
public class FileSelector {

	/**
	 * The file selector dialog.
	 */
	private final Dialog mDialog;

	private Context mContext;

	/** Save or Load file listener. */
	public final OnHandleFileListener mOnHandleFileListener;
	
	/** The list of files and folders which you can choose from */
	private ListView mFileListView;

	/** Button to save/load file */
	private Button mSaveLoadButton;
	/** Cancel Button - close dialog */
	private Button mCancelButton;

	/** Spinner by which to select the file type filtering */
	private Spinner mFilterSpinner;

	private FileOperation mOperation;
	/**
	 * Indicates current location in the directory structure displayed in the
	 * dialog.
	 */
	private File mCurrentLocation;
	
	public static final File mSdCard = Environment.getExternalStorageDirectory();
	public static final String mSdCardAbsolutePath = mSdCard.getAbsolutePath();
	public static final String mPcapRootFolder = mSdCardAbsolutePath + "/logger";
	public static final String mDefaultPcapFolder = mSdCardAbsolutePath + "/logger/pcaptest";
	public static final String mDefaultPcapSaveFolder = mSdCardAbsolutePath + "/logger/pcapsave";
	public static final String mShellFolder = "/data/misc/wifi/shell";
	public static final String mDefaultPcapSaveFile = "/pcapcapture.temp.jp";
	

	/**
	 * Constructor that creates the file selector dialog.
	 * 
	 * @param context
	 *            The current context.
	 * @param operation
	 *            LOAD - to load file / SAVE - to save file
	 * @param onHandleFileListener
	 *            Notified after pressing the save or load button.
	 * @param fileFilters
	 *            Array with filters
	 */
	public FileSelector(final Context context, final FileOperation operation,
			final OnHandleFileListener onHandleFileListener, final String[] fileFilters) {
		mContext = context;
		mOnHandleFileListener = onHandleFileListener;
		mOperation = operation;
		
		if (mSdCard.canRead()) {
			mCurrentLocation = new File(mPcapRootFolder);
		} else {
			mCurrentLocation = Environment.getRootDirectory();
		}
		
		mDialog = new Dialog(context);
		mDialog.setContentView(R.layout.dialog);
		mDialog.setTitle(mCurrentLocation.getAbsolutePath());

		if (mOperation == FileOperation.SAVE) {
			((EditText) mDialog.findViewById(R.id.fileName)).setText("Captures");
		}
		
		prepareFilterSpinner(fileFilters);
		prepareFilesList();

		setSaveLoadButton(operation);

		setCancelButton();
	}

	/**
	 * This method prepares a filter's list with the String's array
	 * 
	 * @param aFilesFilter
	 *            - array of filters, the elements of the array will be used as
	 *            elements of the spinner
	 */
	private void prepareFilterSpinner(String[] fitlesFilter) {
		mFilterSpinner = (Spinner) mDialog.findViewById(R.id.fileFilter);
		if (fitlesFilter == null || fitlesFilter.length == 0) {
			fitlesFilter = new String[] { FileUtils.FILTER_ALLOW_ALL };
			mFilterSpinner.setEnabled(false);
		}
		ArrayAdapter<String> adapter = new ArrayAdapter<String>(mContext, R.layout.spinner_item, fitlesFilter);

		mFilterSpinner.setAdapter(adapter);
		OnItemSelectedListener onItemSelectedListener = new OnItemSelectedListener() {

			@Override
			public void onItemSelected(AdapterView<?> aAdapter, View aView, int arg2, long arg3) {
				TextView textViewItem = (TextView) aView;
				String filtr = textViewItem.getText().toString();
				makeList(mCurrentLocation, filtr);
			}

			@Override
			public void onNothingSelected(AdapterView<?> arg0) {

			}
		};
		mFilterSpinner.setOnItemSelectedListener(onItemSelectedListener);
	}

	/**
	 * This method prepares the mFileListView
	 * 
	 */
	private void prepareFilesList() {
		mFileListView = (ListView) mDialog.findViewById(R.id.fileList);

		mFileListView.setOnItemClickListener(new OnItemClickListener() {

			@Override
			public void onItemClick(final AdapterView<?> parent, final View view, final int position, final long id) {
				// Check if "../" item should be added.
				((EditText) mDialog.findViewById(R.id.fileName)).setText("");
				if (id == 0) {
					final String parentLocation = mCurrentLocation.getParent();
					if (parentLocation != null) { // text == "../"
						String fileFilter = ((TextView) mFilterSpinner.getSelectedView()).getText().toString();
						mCurrentLocation = new File(parentLocation);
						makeList(mCurrentLocation, fileFilter);
					} else {
						onItemSelect(parent, position);
					}
				} else {
					onItemSelect(parent, position);
				}
			}
		});
		String filtr = mFilterSpinner.getSelectedItem().toString();
		makeList(mCurrentLocation, filtr);
	}

	/**
	 * The method that fills the list with a directories contents.
	 * 
	 * @param location
	 *            Indicates the directory whose contents should be displayed in
	 *            the dialog.
	 * @param fitlesFilter
	 *            The filter specifies the type of file to be displayed
	 */
	private void makeList(final File location, final String fitlesFilter) {
		final ArrayList<FileData> fileList = new ArrayList<FileData>();
		final String parentLocation = location.getParent();
		if (parentLocation != null) {
			// First item on the list.
			fileList.add(new FileData("../", FileData.UP_FOLDER));
		}
		File listFiles[] = location.listFiles();
		if (listFiles != null) {
			ArrayList<FileData> fileDataList = new ArrayList<FileData>();
			for (int index = 0; index < listFiles.length; index++) {
				File tempFile = listFiles[index];
				if (FileUtils.accept(tempFile, fitlesFilter)) {
					int type = tempFile.isDirectory() ? FileData.DIRECTORY : FileData.FILE;
					fileDataList.add(new FileData(listFiles[index].getName(), type));
				}
			}
			fileList.addAll(fileDataList);
			Collections.sort(fileList);
		}
		// Fill the list with the contents of fileList.
		if (mFileListView != null) {
			FileListAdapter adapter = new FileListAdapter(mContext, fileList);
			mFileListView.setAdapter(adapter);
		}
	}

	/**
	 * Handle the file list item selection.
	 * 
	 * Change the directory on the list or change the name of the saved file if
	 * the user selected a file.
	 * 
	 * @param parent
	 *            First parameter of the onItemClick() method of
	 *            OnItemClickListener. It's a value of text property of the
	 *            item.
	 * @param position
	 *            Third parameter of the onItemClick() method of
	 *            OnItemClickListener. It's the index on the list of the
	 *            selected item.
	 */
	private void onItemSelect(final AdapterView<?> parent, final int position) {
		final String itemText = ((FileData) parent.getItemAtPosition(position)).getFileName();
		final String itemPath = mCurrentLocation.getAbsolutePath() + File.separator + itemText;
		final File itemLocation = new File(itemPath);

		if (!itemLocation.canRead()) {
			Toast.makeText(mContext, "Access denied!!!", Toast.LENGTH_SHORT).show();
		} else if (itemLocation.isDirectory()) {
			mCurrentLocation = itemLocation;
			String fileFilter = ((TextView) mFilterSpinner.getSelectedView()).getText().toString();
			makeList(mCurrentLocation, fileFilter);
		} else if (itemLocation.isFile()) {
			final EditText fileName = (EditText) mDialog.findViewById(R.id.fileName);
			fileName.setText(itemText);
		}
	}

	/**
	 * Set button name and click handler for Save or Load button.
	 * 
	 * @param operation
	 *            Performed file operation.
	 */
	private void setSaveLoadButton(final FileOperation operation) {
		mSaveLoadButton = (Button) mDialog.findViewById(R.id.fileSaveLoad);
		switch (operation) {
		case SAVE:
			mSaveLoadButton.setText(R.string.saveButtonText);
			break;
		case LOAD:
			mSaveLoadButton.setText(R.string.loadButtonText);
			break;
		}
		mSaveLoadButton.setOnClickListener(new SaveLoadClickListener(operation, this, mContext));
	}


	/** Set onClick() event handler for the cancel button. */
	private void setCancelButton() {
		mCancelButton = (Button) mDialog.findViewById(R.id.fileCancel);
		mCancelButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(final View view) {
				mDialog.cancel();
			}
		});
	}

	public String getSelectedFileName() {
		final EditText fileName = (EditText) mDialog.findViewById(R.id.fileName);
		return fileName.getText().toString();
	}

	public File getCurrentLocation() {
		return mCurrentLocation;
	}

	/** Simple wrapper around the Dialog.show() method. */
	public void show() {
		mDialog.show();
	}

	/** Simple wrapper around the Dialog.dissmiss() method. */
	public void dismiss() {
		mDialog.dismiss();
	}
	
	/** Just copy default test pcap files. */	
	public static void doCopyDefaultPcapFiles(Context context) {
	 	
	    if ( Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED) ) {

	    	if (mSdCard.canRead() == false) {
	    		return;
	    	}
	    	
		    File saveDir = new File(mDefaultPcapSaveFolder);
	        if (saveDir.exists() == false) {
		        saveDir.mkdirs();
	        }
	        
		    File outDir = null;
	        outDir = new File(mDefaultPcapFolder);
	        if (outDir.exists() == true) {
	        	return;
	        }
	        outDir.mkdirs();
	        
	        InputStream is = null;
	        OutputStream os = null;
	        try {                        		        
	        	String[] fileList = context.getAssets().list("pcap");  
	        	for (int i = 0; i < fileList.length; i++) {
		        		
		            is = context.getAssets().open("pcap/" + fileList[i]);
		            int size = is.available();
		                      
		    	    File outfile = new File(outDir, fileList[i]);
		            outfile.createNewFile();         
		            os = new FileOutputStream(outfile);
		            
		            byte[] buffer = new byte[size];
		            
		            is.read(buffer);
		            os.write(buffer);
		            
		            is.close();
		            os.close();
	        	}
	        } catch (Exception e) {
	            e.printStackTrace();
	        } finally {
	            try {
	            	if (is != null) is.close();
	                if (os != null) os.close();
	            } catch (IOException e) {
	                // TODO Auto-generated catch block
	                e.printStackTrace();
	            }
	        }
	    }
	}
}
