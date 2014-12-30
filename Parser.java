import java.util.Date;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class Parser {
	
	
	
	public void parse(String PCAP_file_path) {
		
		StringBuilder err = new StringBuilder();
		Pcap pcap = Pcap.openOffline(PCAP_file_path, err);
		
		if(pcap == null) {
			System.err.printf("Error while opening device for capture: ");
			return;
		}
		
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			
			public void nextPacket(PcapPacket packet, String user) {
				
				PcapPacket.setFormatter(new JSONFormatter());
				
				String xml_string = packet.toString();
				
				int junk_start_index = xml_string.indexOf("java.io");
				
				if(junk_start_index > -1) {
					xml_string = xml_string.substring(0,xml_string.indexOf("java.io"));
				}
				
				System.out.println(xml_string);
				
			}
		};
		
		pcap.loop(1, jpacketHandler, "");
	}
	
	
	
	public static void main(String[] args) {
		String PCAP_file_path = "/home/puaykai/Downloads/orange1.5.cap";
		
		Parser parser = new Parser();
		
		parser.parse(PCAP_file_path);
	}

}
