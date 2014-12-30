
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
			
			System.out.println("Length:"+this.JSON.length());
		}
	}
	
	private String convertToDesiredFormat(String old_JSON) {
		String new_JSON = "";
		
		System.out.println(old_JSON.replace('\n', ' '));
		
		JSONObject obj = new JSONObject();
		
		JSONParser json_parser = new JSONParser();
		
		try {
			JSONArray array = (JSONArray)json_parser.parse(old_JSON);
			
			obj = (JSONObject) array.get(0);
			
			System.out.println(obj.toJSONString());
			
			int number_of_headers = array.size() -1;
			
			for(int i=0; i<number_of_headers; i++) {
				array.get(i+1);
			}
			
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
		System.out.println("*************************");
		System.out.println(JSON_string);
		System.out.println("*************************");
		convertToDesiredFormat(JSON_string);
	}
	
	
	
	public static void main(String[] args) {
		String PCAP_file_path = "/home/puaykai/Downloads/orange1.5.cap";
		
		Parser parser = new Parser();
		
		parser.parse(PCAP_file_path);
	}

}
