import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.sql.Timestamp;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.structure.JField;
import org.json.simple.JSONObject;

public class JSONFormatter extends JFormatter{

	/** The Constant PAD. */
	private static final String PAD = "  ";

	/** The Constant LT. */
	private static final String LT = "{";

	/** The Constant GT. */
	private static final String GT = "}";
	
	private int number_of_headers;
	
	private boolean last_out_is_array = false;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#end(org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JField,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param field
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#fieldAfter(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.structure.JField, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void fieldAfter(JHeader header, JField field, Detail detail)
			throws IOException {
		
		if(field == null) {
			System.out.println("***************************************FIELD AFTER NULL ***********************************************");
		}

		if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {
			decLevel();
			//pad().format(GT);//pad().format(LT + "/hexdump" + GT + "\n");
		} /*
			 * else if (false && field.hasSubFields()) { final String v =
			 * stylizeSingleLine(header, field, field.getValue(header));
			 * 
			 * pad().format(LT + "/field" + GT);
			 * 
			 * }
			 */else if (field.getStyle() == Style.INT_BITS) {
		}

		decLevel();
		
		this.last_out_is_array = true;
	}

	/**
	 * Instantiates a new JSON formatter.
	 */
	public JSONFormatter() {
		super();
	}

	/**
	 * Instantiates a new JSON formatter.
	 * 
	 * @param out
	 *          the out
	 */
	public JSONFormatter(Appendable out) {
		super(out);
	}

	/**
	 * Instantiates a new xml formatter.
	 * 
	 * @param out
	 *          the out
	 */
	public JSONFormatter(StringBuilder out) {
		super(out);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#start(org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JField,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * jnetpcap.jar mis-classified ARP sha value as <ul>BYTE_ARRAY_IP4_ADDRESS</ul>, when it should be <ul>BYTE_ARRAY_COLON_ADDRESS</ul>
	 * @param header
	 * @param field
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#fieldBefore(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.structure.JField, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void fieldBefore(JHeader header, JField field, Detail detail)
			throws IOException {
		
		//This line is to correct jnetpcap bug of misclassifying ARP sha value as IP4ADDRESS format
		//TODO remove after jnetpcap is updated

		
		String comma = "";
		if(this.last_out_is_array) {
			comma = ",";
		}else {
			comma = "";
		}
		
		if(field == null || header == null || detail == null) {
			System.out.println("********************************NULL FIELD***********************************");
			System.out.println();
			pad().format(comma+LT//pad().format(LT//
					+ "\"name\":\"%s\", \"value\":\"%s\""+ GT, //+ "field name=\"%s\" value=\"%s\" offset=\"%d\" length=\"%d\"/" + GT,//
					field.getName(),
					"null");
			return;
		}

		incLevel(PAD);

		
		if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {
			
			final String[] v =
					stylizeMultiLine(header,
							field,
							Style.BYTE_ARRAY_HEX_DUMP_NO_TEXT,
							field.getValue(header));
			String i_comma = "";
			if(v.length != 0) {
				i_comma = ",";
			}
			
			pad().format(LT +"\"name\" :\"hexdump\", "+ "\"offset\":\"%d\", \"length\":\"%d\"" + GT+i_comma,//pad().format(LT + "hexdump offset=\"%d\" length=\"%d\"" + GT,
					field.getOffset(header),
					field.getLength(header));
			incLevel(PAD);

			incLevel(PAD);
			
			i_comma = ",";
			for(int index = 0; index<v.length; index++) {//for (String i : v) {
				String i = v[index];
				
				if(index == v.length-1) {
					i_comma = "";
				}
				
				pad().format(LT +"\"name\" :\"hexline\", "+ "\"data\":\"%s\"" + GT+i_comma, i.trim());//pad().format(LT + "hexline data=\"%s\"/" + GT, i.trim());
			}
			this.last_out_is_array = true;

			decLevel();

		} /*
			 * else if (false && field.hasSubFields()) { final String v =
			 * stylizeSingleLine(header, field, field.getValue(header));
			 * 
			 * pad().format( LT +
			 * "field name=\"%s\" value=\"%s\" offset=\"%d\" length=\"%d\"" + GT,
			 * field.getName(), v, field.getOffset(header), field.getLength(header));
			 * 
			 * }
			 */else if (field.getStyle() == Style.INT_BITS) {
		} else if (field.getStyle() == Style.BYTE_ARRAY_ARRAY_IP4_ADDRESS) {
			byte[][] table = (byte[][]) field.getValue(header);

			for (byte[] b : table) {
				final String v = stylizeSingleLine(header, field, b);
				pad().format(comma+"\"ip4\":"+LT + "\"%s\" " + GT , v);//pad().format(LT + "ip4=\"%s\" /" + GT, v);
			}

			incLevel(0); // Inc for multi line fields
		} else {
			//System.out.println("FIELD************************************************************");
			//System.out.println(field);
			//System.out.println(field.getValue(header));
			//System.out.println(stylizeSingleLine(
			//		header, 
			//		field, 
			//		field.getValue(
			//				header)));
			final String v = JSONObject.escape(stylizeSingleLine(header, field, field.getValue(header)));
			pad().format(comma+LT//pad().format(LT//
					+ "\"name\":\"%s\", \"value\":\"%s\", \"offset\":\"%d\", \"length\":\"%d\"" + GT ,//+ "field name=\"%s\" value=\"%s\" offset=\"%d\" length=\"%d\"/" + GT,//
					field.getName(),
					v,
					field.getOffset(header),
					field.getLength(header));
		}
		
		this.last_out_is_array = true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#end(org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#headerAfter(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerAfter(JHeader header, Detail detail) throws IOException {

		if(header.getIndex() == this.number_of_headers-1) {
			
			if(this.last_out_is_array) {
				pad().format("]"+GT);//pad().format(LT + "/header" + GT);
			}else{
				pad().format(GT);//pad().format(LT + "/header" + GT);
			}
		} else {
			if(this.last_out_is_array) {
				pad().format("]"+GT+",");//pad().format(LT + "/header" + GT);
			} else{
				pad().format(GT+",");//pad().format(LT + "/header" + GT);
			}
			
		}
		
		pad();
		
		//header.getIndex();
		last_out_is_array = false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#start(org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#headerBefore(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerBefore(JHeader header, Detail detail) throws IOException {
		if(this.last_out_is_array) {
			this.last_out_is_array = false;
			pad().format("]");
		}
		
		if(header.getIndex() == -1 ) {
			pad().format(",");
		}
		pad().format("\""+header.getName()+"\":"+LT +"\"info\":"+LT+ "\"name\":\"%s\",", header.getName());//pad().format(LT + "header name=\"%s\"", header.getName());
		incLevel(PAD + PAD);

		pad().format("\"nicname\":\"%s\",", header.getNicname());//pad().format("nicname=\"%s\"", header.getNicname());//
		pad().format("\"classname\":\"%s\",", header.getClass().getCanonicalName());//pad().format("classname=\"%s\"", header.getClass().getCanonicalName());//
		pad().format("\"offset\":\"%d\",", header.getOffset());//pad().format("offset=\"%d\"", header.getOffset());//
		
		if(header.getFields().length == 0){
			pad().format("\"length\":\"%d\"" + GT , header.getLength());//pad().format("length=\"%d\"" + GT, header.getLength());//
		}else {
			pad().format("\"length\":\"%d\"" + GT + ",\"fields\":[", header.getLength());//pad().format("length=\"%d\"" + GT, header.getLength());//
		}
		
		decLevel();
		
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#packetAfter(org.jnetpcap.packet.JPacket
	 * , org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param packet
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#packetAfter(org.jnetpcap.packet.JPacket, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetAfter(JPacket packet, Detail detail) throws IOException {

		decLevel();
		pad().format(GT);//pad().format(LT + "/packet" + GT);
		
		
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#packetBefore(org.jnetpcap.packet.
	 * JPacket, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param packet
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#packetBefore(org.jnetpcap.packet.JPacket, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetBefore(JPacket packet, Detail detail) throws IOException {
		this.number_of_headers = packet.getHeaderCount();
		
		pad().format(LT+"\"packet\":"+LT);//pad().format(LT + "packet");

		incLevel(PAD + PAD);

		pad().format("\"wirelen\":\"%d\",", packet.getCaptureHeader().wirelen());//pad().format("wirelen=\"%d\"", packet.getCaptureHeader().wirelen());//
		pad().format("\"caplen\":\"%d\",", packet.getCaptureHeader().caplen());

		if (frameIndex != -1) {
			pad().format("\"index\":\"%d\",", frameIndex);//pad().format("index=\"%d\"", frameIndex);//
		}

		pad().format("\"timestamp\":\"%s\",",//pad().format("timestamp=\"%s\"",//
				new Timestamp(packet.getCaptureHeader().timestampInMillis()));
		pad().format("\"captureSeconds\":\"%s\",", packet.getCaptureHeader().seconds());//pad().format("captureSeconds=\"%s\"", packet.getCaptureHeader().seconds());//
		pad().format("\"captureNanoSeconds\":\"%s\"" + GT +",",//pad().format("captureNanoSeconds=\"%s\"" + GT,
				packet.getCaptureHeader().nanos());
		pad();

		decLevel();

		incLevel(PAD);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#subHeaderAfter(org.jnetpcap.packet
	 * .JHeader, org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param subHeader
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#subHeaderAfter(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.JHeader, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void subHeaderAfter(JHeader header, JHeader subHeader, Detail detail)
			throws IOException {

		headerAfter(subHeader, detail);
		decLevel();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.format.JFormatter#subHeaderBefore(org.jnetpcap.packet
	 * .JHeader, org.jnetpcap.packet.JHeader,
	 * org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	/** 
	 * @param header
	 * @param subHeader
	 * @param detail
	 * @throws IOException
	 * @see org.jnetpcap.packet.format.JFormatter#subHeaderBefore(org.jnetpcap.packet.JHeader, org.jnetpcap.packet.JHeader, org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void subHeaderBefore(JHeader header,
			JHeader subHeader,
			Detail detail) throws IOException {

		incLevel(PAD);
		pad();

		headerBefore(subHeader, detail);
	}

}
