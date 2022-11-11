package navid.fana;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

public class SnmpManagerV3 {

    public static final int SNMP_VERSION = SnmpConstants.version3;
    public static final String SNMP_READ_COMMUNITY = "public";

//    OID of MIB RFC 1213; Scalar Object = .iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0
//    .1.3.6.1.2.1.1.1.0
    public static final String SAMPLE_DEVICE_OID = ".1.3.6.1.2.1.1.1.0";
    public static final String SNMP_AGENT_ADDRESS = "127.0.0.1";
    public static final String SNMP_AGENT_PORT = "161";
    public static final int SNMP_PDU_TYPE = PDU.GET;

    public static final int SNMP_V3_SECURITY_LEVEL = SecurityLevel.AUTH_PRIV;
    public static final OctetString SNMP_V3_SECURITY_NAME =new OctetString("authPrivUser");
    public static final String SNMP_V3_USERNAME = "snmpuser";
    public static final String SNMP_V3_PASSWORD = "1qaz2wsx";
    public static final OID SNMP_V3_AUTH_PROTOCOL = AuthSHA.ID;
    public static final OID SNMP_V3_PRIVATE_KEY_PROTOCOL = PrivAES128.ID;
    public static final String SNMP_V3_PRIVATE_PASSWORD = "2wsx3edc";

    public static void main(String[] args) throws IOException {
        String address = SNMP_AGENT_ADDRESS + "/" + SNMP_AGENT_PORT;
        Address address1 = new UdpAddress(address);
        TransportMapping transportMapping = new DefaultUdpTransportMapping();

//      UserTarget class used for SNMP v3
//        UserTarget target = new UserTarget<>();
        UserTarget target = new UserTarget();
        target.setAddress(address1);
        target.setVersion(SNMP_VERSION);
        target.setRetries(2);
        target.setTimeout(1000);
//      Security configs for SNMP v3 target
        target.setSecurityLevel(SNMP_V3_SECURITY_LEVEL);
        target.setSecurityName(new OctetString(SNMP_V3_USERNAME));

//      create and add user security model
        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
        SecurityModels.getInstance().addSecurityModel(usm);

//      user credentials
//      OctetString securityName = new OctetString(SNMP_V3_SECURITY_NAME);
        OctetString authPassphrase = new OctetString(SNMP_V3_PASSWORD);
        OctetString privPassphrase = new OctetString(SNMP_V3_PRIVATE_PASSWORD);
        OID authProtocol = SNMP_V3_AUTH_PROTOCOL;
        OID privProtocol = SNMP_V3_PRIVATE_KEY_PROTOCOL;

        UsmUser usmUser = new UsmUser(new OctetString(SNMP_V3_USERNAME), authProtocol, authPassphrase, privProtocol, privPassphrase);


        ScopedPDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(new OID(SAMPLE_DEVICE_OID)));
        pdu.setType(SNMP_PDU_TYPE);

        Snmp snmp ;
        ResponseEvent responseEvent;
        snmp = new Snmp(transportMapping);
        snmp.getUSM().addUser(SNMP_V3_SECURITY_NAME, usmUser);
        snmp.listen();
        System.out.println("Sending SNMP GET request to "+ SNMP_AGENT_ADDRESS+"/"+SNMP_AGENT_PORT+".\n" + pdu);
        responseEvent = snmp.send(pdu,target);

        try {
            if (responseEvent != null) {
//            System.out.println("Response is not null.");
                if (responseEvent.getResponse().getErrorStatusText().equalsIgnoreCase("success")) {
                    PDU responsePDU = responseEvent.getResponse();
                    System.out.println("\nSNMP GET Response:\n" + responsePDU.getVariableBindings().get(0));
                } else {
                    System.out.println("SNMP GET Request failed.\n Printing the response:\n\t" + responseEvent.getResponse());
                    System.out.println("Printing SNMP GET Request PDU:\n" + responseEvent.getRequest());
                }
            } else {
                System.out.println("SNMP GET Request time oue.");
            }
        } catch (Exception exception){
            exception.printStackTrace();
            System.out.println("*******************************************************************************");
            System.out.println("Response Event Error: \n"+responseEvent.getError());
//            System.out.println("Response Event: \n"+responseEvent.getError());
            System.out.println("*******************************************************************************");
        }
        snmp.close();
    }

}
