
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import java.util.Map.Entry;

import javax.naming.Context;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.tcpip.Http;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * This class depends on the following jars: <br>
 * 	1. jnetpcap.jar <ul>http://softlayer-dal.dl.sourceforge.net/project/jnetpcap/jnetpcap/1.3/jnetpcap-1.3.0-1.ubuntu.x86_64.tgz</ul><br>
 *  2. json-simple-1.1.1.jar <ul>https://json-simple.googlecode.com/files/json-simple-1.1.1.jar</ul><br>
 * */
public class Parser {
	
	private String JSON;
	private JSONObject resultant_JSON;
	
	private ArrayList<String> list_of_packet_strings = new ArrayList<String>();
	private ArrayList<JSONObject> list_of_packet_object = new ArrayList<JSONObject>();
	
	public ArrayList<String> getListOfPacketStrings() {
		return this.list_of_packet_strings;
	}
	
	public String getJSON () {
		return this.JSON;
	}
	
	private void setJSON(String JSON) {
		this.JSON = JSON;
	}
	
	private void setJSONObj(JSONObject resultant_JSON) {
		this.resultant_JSON = resultant_JSON;
	}
	
	public JSONObject getJSONObject() {
		return this.resultant_JSON;
	}
	
	private boolean hasHTTPHeader = false;
	
	private void sethasHTTPHeader(boolean hasHTTPHeader) {
		this.hasHTTPHeader = hasHTTPHeader;
	}
	
	public void addPacketString(String JSON) {
		list_of_packet_strings.add(JSON);
	}
	
	public void addPacketJSON(JSONObject object) {
		list_of_packet_object.add(object);
	}
	
	public class myPcapPacketHandler implements PcapPacketHandler<Context>{
		
		@Override
		public void nextPacket(PcapPacket packet, Context user) {
			
			try {
				
				JSONObject obj = new JSONObject();
				
				Http http = new Http();
				if(packet.hasHeader(http)) {
					//System.out.println("HAS HTTP ************************");
					sethasHTTPHeader(true);
					JField[] http_fields = http.getFields();
					for(JField field : http_fields) {
						if(field.hasField(http)) {
							obj.put(field.getName(), field.getValue(http));
						}
					}
				}
				
				StringBuilder builder  = new StringBuilder();
				
				PcapPacket.setFormatter(new JSONFormatter(builder));
				
				packet.toString();
				
				String temp_json_string = builder.toString();
				

				
				setJSON(temp_json_string);
				
				JSONParser json_parser = new JSONParser();
				
				JSONObject temp_JSON = (JSONObject) json_parser.parse(temp_json_string);
				
				temp_JSON.put("Http", obj);
				
				//setJSONObj(temp_JSON);
				
				//addPacketJSON(temp_JSON);
				
				user.write(NullWritable.get(), new Text(convertToDesiredFormat(temp_JSON)));
				
				if(packet.hasHeader(http)) {
					//System.out.println(temp_JSON);
				}
				
			} catch (Exception e) {

			}
		}
	}
	
	private void convertAllToDesiredFormat() {
		for(JSONObject array : this.list_of_packet_object) {
			this.addPacketString(convertToDesiredFormat(array));
		}
	}
	
	private String convertToDesiredFormat(JSONObject array) {
		String new_JSON = "";
		
		JSONObject obj = new JSONObject();
		
		try {
			
			//JSONObject array = getJSONObject();
			
			if(array == null) {
				
				JSONParser json_parser = new JSONParser();
				
				array = (JSONObject) json_parser.parse(getJSON());
			}
			
			JSONObject frame = (JSONObject) array.get("packet");
			
			obj.put("Frame", frame);
			
			int number_of_headers = array.size() -1;
			
			Set<Entry<Object, Object>> set = array.entrySet();
			
			for(Entry<Object, Object> e : set) {
				
				String header_name = (String) e.getKey();
				
				if(header_name.equals("packet")) continue;
				
				JSONObject header = (JSONObject) e.getValue();

				if(!header.isEmpty()) obj.put(header_name, parseHeader(header));
			}
			
			this.setJSONObj(obj);
			
			new_JSON = obj.toJSONString();
			
			this.setJSON(new_JSON);
			
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		return this.getJSON();
	}
	
	private JSONObject parseHeader(JSONObject header) {
		JSONObject header_obj = new JSONObject();
		
		JSONObject info = (JSONObject) header.get("info");
		
		JSONArray fields = (JSONArray) header.get("fields");
		
		//System.out.println("parseHeader: *********************");
		//System.out.println(header);
		//System.out.println("**********************************");
		
		if(fields == null || info == null) {//TODO find out why there is a null
			return header_obj;
		}
		
		String nic_name = (String) info.get("nicname");
		
		header_obj.put("nicname", nic_name);
		
		Iterator<Object> iterator = fields.iterator();
		
		while(iterator.hasNext()) {
			JSONObject field = (JSONObject) iterator.next();
			String field_name = (String) field.get("name");
			String field_value = (String) field.get("value");
			if(field_value == null) field_value = (String) field.get("data");
			header_obj.put(field_name, field_value);
		}
		
		if(header.size() > 2) {
			Set<Entry<Object, Object>> set = header.entrySet();
			
			for(Entry<Object, Object> e : set) {
				String name = (String) e.getKey();
				if(name.equals("info") || name.equals("fields")) continue;
				header_obj.put(name, parseHeader((JSONObject) e.getValue()));
			}
		}
		
		return header_obj;
	}
	
	public void parse(String PCAP_file_path, Context user) {
		
		StringBuilder err = new StringBuilder();
		Pcap pcap = Pcap.openOffline(PCAP_file_path, err);
		
		if(pcap == null) {
			System.err.printf("Error while opening device for capture: ");
			return ;
		}
		
		myPcapPacketHandler jpacketHandler = new myPcapPacketHandler();
		
		pcap.loop(0, jpacketHandler, user);
		
		//convertAllToDesiredFormat();
		
		//JSONObject obj = this.getJSONObject();
		
		//obj.put("file_path", PCAP_file_path);
		
		//this.setJSON(obj.toJSONString());
		
		//this.setJSONObj(obj);
		
		//if(this.hasHTTPHeader)System.out.println(this.getJSON());
		//System.out.println("*****************");
		//System.out.println(JSON_string);
		//System.out.println("*****************");
		//return this.getJSON();
		
	}
	
	
	
	public static void main(String[] args) {
		String PCAP_file_path = "/home/puaykai/Downloads/orange1.5.cap";
		//TODO add fiel_path to JSOn
		/*
		Parser parser = new Parser();
		
		parser.parse(PCAP_file_path);
		
		for(String JSON_string : parser.getListOfPacketStrings()) {
			System.out.println(JSON_string);
		}
		*/
	}

}
