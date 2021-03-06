package pcapmonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.lge.pcapmonitor.R;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.view.ViewGroup;
import graph.hzgrapherlib.animation.GraphAnimation;
import graph.hzgrapherlib.graphview.ScatterGraphView;
import graph.hzgrapherlib.vo.GraphNameBox;
import graph.hzgraphlib.vo.scattergraph.ScatterGraph;
import graph.hzgraphlib.vo.scattergraph.ScatterGraphVO;
import jpcap.packet.Packet;

public class TabActivityScatterGraph extends Activity implements IWidgetViewActivity 
{
	public static final String TAG = TabActivityScatterGraph.class.getSimpleName();
	
	private ViewGroup layoutGraphView;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) 
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_graph);
		
		setScatterGraph();
		
	}
	
	
	private void setScatterGraph()
	{
		ScatterGraphVO vo = getScatterGraphInfo();
		
		layoutGraphView = (ViewGroup) findViewById(R.id.layoutGraphView);
		layoutGraphView.addView(new ScatterGraphView(this, vo));
		
	}
	
	
	private ScatterGraphVO getScatterGraphInfo()
	{
		int paddingBottom = ScatterGraphVO.DEFAULT_PADDING;
		int paddingTop = ScatterGraphVO.DEFAULT_PADDING;
		int paddingLeft = ScatterGraphVO.DEFAULT_PADDING;
		int paddingRight = ScatterGraphVO.DEFAULT_PADDING;
		int marginTop = ScatterGraphVO.DEFAULT_MARGIN_TOP;
		int marginRight = 10;
		int maxValueX = 100;
		int maxValueY = 200;
		int incrementX = 20;
		int incrementY = 50;
	
		
		Random random = new Random();
		int count = 100;
			
		List<ScatterGraph> arrGraph = new ArrayList<ScatterGraph>();
		for(int i=0; i<count; i++){
			int caseId = random.nextInt(2);
			switch(caseId){
				case 0:
					float x = random.nextInt(maxValueY);
					float y = random.nextInt(maxValueX);
					arrGraph.add(new ScatterGraph("Android", Color.GREEN, new float[]{x, y}));
					break;
					
				case 1:
					float xios = random.nextInt(maxValueY);
					float yios = random.nextInt(maxValueX);
					arrGraph.add(new ScatterGraph("iOS", Color.BLUE, new float[]{xios, yios}));
					break;
			}			
		}
				
		ScatterGraphVO vo = new ScatterGraphVO(new String[]{"Android","iOS"}, arrGraph,
													paddingTop, paddingBottom, paddingLeft, paddingRight,
													marginTop, marginRight, maxValueX, maxValueY,
													incrementX, incrementY);
		vo.setAnimation(new GraphAnimation());
		vo.setGraphNameBox(new GraphNameBox());
		return vo;
		
	}


	@Override
	public void setPacket(Packet packet) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void updateView() {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void initializeAll() {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void initializeInterfaceFunction() {
		// TODO Auto-generated method stub
		
	}


	@Override
	public Handler getHandler() {
		// TODO Auto-generated method stub
		return null;
	}
	

}
