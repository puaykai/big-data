
import java.util.Iterator;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
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
	
	public class myPcapPacketHandler implements PcapPacketHandler<String>{
		private String JSON;
		
		public String getJSON () {
			return this.JSON;
		}

		@Override
		public void nextPacket(PcapPacket packet, String user) {
			
			StringBuilder builder  = new StringBuilder();
			
			PcapPacket.setFormatter(new JSONFormatter(builder));
			
			packet.toString();
			
			this.JSON = builder.toString();
			
		}
	}
	
	private String convertToDesiredFormat(String old_JSON) {
		String new_JSON = "";
		
		JSONObject obj = new JSONObject();
		
		JSONParser json_parser = new JSONParser();
		
		try {
			JSONObject array = (JSONObject)json_parser.parse(old_JSON);
			
			obj = (JSONObject) array.get("packet");
			
			int number_of_headers = array.size() -1;
			
			for(int i=0; i<number_of_headers; i++) {
				
				JSONObject header = (JSONObject) array.get("header"+i);
				
				JSONObject info = (JSONObject) header.get("info");
				
				JSONArray fields = (JSONArray) header.get("fields");
				
				String header_name = (String)info.get("name");
				
				String nic_name = (String) info.get("nicname");
				
				JSONObject header_obj = new JSONObject();
				
				header_obj.put("nicname", nic_name);
				
				Iterator<Object> iterator = fields.iterator();
				
				while(iterator.hasNext()) {
					JSONObject field = (JSONObject) iterator.next();
					String field_name = (String) field.get("name");
					String field_value = (String) field.get("value");
					if(field_value == null) field_value = (String) field.get("data");
					header_obj.put(field_name, field_value);
				}
				
				obj.put(header_name, header_obj);
			}
			
			System.out.println(obj.toJSONString());
			
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		return new_JSON;
	}
	
	public void parse(String PCAP_file_path) {
		
		StringBuilder err = new StringBuilder();
		Pcap pcap = Pcap.openOffline(PCAP_file_path, err);
		
		if(pcap == null) {
			System.err.printf("Error while opening device for capture: ");
			return;
		}
		
		myPcapPacketHandler jpacketHandler = new myPcapPacketHandler();
		
		pcap.loop(1, jpacketHandler, "");
		
		String JSON_string = jpacketHandler.getJSON();

		convertToDesiredFormat(JSON_string);
	}
	
	
	
	public static void main(String[] args) {
		String PCAP_file_path = "/home/puaykai/Downloads/orange1.5.cap";
		
		Parser parser = new Parser();
		
		parser.parse(PCAP_file_path);
	}

}
