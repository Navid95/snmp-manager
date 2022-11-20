package navid.fana.nms;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SimpleNms {

    private  int SNMP_VERSION = SnmpConstants.version3;
    private  String SNMP_READ_COMMUNITY = "public";
    private  String SAMPLE_DEVICE_OID = "1.3.6.1.2.1.1.2";
    private  String SNMP_AGENT_ADDRESS = "127.0.0.1";
    private  String SNMP_AGENT_PORT = "2001";
    private  int SNMP_PDU_TYPE = PDU.GET;
    private  int SNMP_V3_SECURITY_LEVEL = SecurityLevel.AUTH_PRIV;
    private  OctetString SNMP_V3_SECURITY_NAME =new OctetString("authPrivUser");
    private  String SNMP_V3_USERNAME = "snmpuser";
    private  String SNMP_V3_PASSWORD = "1qaz2wsx";
    private  OID SNMP_V3_AUTH_PROTOCOL = AuthSHA.ID;
    private  OID SNMP_V3_PRIVATE_KEY_PROTOCOL = PrivAES128.ID;
    private String SNMP_V3_PRIVATE_PASSWORD = "2wsx3edc";
    private int SNMP_RETRY_COUNT = 2;
    private int SNMP_TIME_OUT = 1000;

    private TransportMapping transportMapping;
    private UserTarget userTarget;
    private OctetString localEngineId;
    private UsmUser usmUser;
    private USM usm;
    private ScopedPDU scopedPDU;
    private Snmp snmp;
    private ResponseEvent responseEvent;
    private Address address;

    public SimpleNms() throws IOException {
        transportMapping = new DefaultUdpTransportMapping();
        userTarget = new UserTarget();
        localEngineId = new OctetString(MPv3.createLocalEngineID());
        usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
        SecurityModels.getInstance().addSecurityModel(usm);
        scopedPDU = new ScopedPDU();
        snmp = new Snmp(transportMapping);

    }

    public void init(Address address, String username, String password, String privateKey) throws IOException {
        this.address = address;
        editTarget(this.address, this.SNMP_V3_SECURITY_LEVEL, username);
        editUsmUser(username, password, privateKey);
//        this.snmp.getUSM().addUser(new OctetString(this.SNMP_V3_USERNAME),this.usmUser);
        this.snmp.getUSM().addUser(new OctetString(username),this.usmUser);
        snmpListen();
    }

    private void editTarget(Address address, int securityLevel,String securityName) {
        this.address = address;
        userTarget.setAddress(this.address);
        userTarget.setVersion(this.SNMP_VERSION);
        userTarget.setRetries(this.SNMP_RETRY_COUNT);
        userTarget.setTimeout(this.SNMP_TIME_OUT);
//      Security configs for SNMP v3 target
//        userTarget.setSecurityLevel(this.SNMP_V3_SECURITY_LEVEL);
        userTarget.setSecurityLevel(securityLevel);
//        userTarget.setSecurityName(new OctetString(this.SNMP_V3_USERNAME));
        userTarget.setSecurityName(new OctetString(securityName));
    }

    private void editUsmUser(String username, String password, String privateKey) {
        OctetString authPassphrase = new OctetString(password);
        OctetString privPassphrase = new OctetString(privateKey);
        this.usmUser = new UsmUser(new OctetString(username), this.SNMP_V3_AUTH_PROTOCOL, authPassphrase, this.SNMP_V3_PRIVATE_KEY_PROTOCOL, privPassphrase);
//        this.usmUser = new UsmUser(new OctetString(this.SNMP_V3_USERNAME), this.SNMP_V3_AUTH_PROTOCOL, new OctetString(this.SNMP_V3_PASSWORD), this.SNMP_V3_PRIVATE_KEY_PROTOCOL, new OctetString(this.SNMP_V3_PRIVATE_PASSWORD));
    }

    private void snmpListen() throws IOException {
        this.snmp.listen();
    }

    private void snmpClose() throws IOException {
        this.snmp.close();
    }

    public ResponseEvent snmpGet(List<OID> oidList) throws IOException {
        scopedPDU.clear();
        List<VariableBinding> variableBindingList = new ArrayList<>();
        for (OID oid:oidList) {
            variableBindingList.add(new VariableBinding(oid));
        }
        for (VariableBinding variableBinding:variableBindingList) {
            this.scopedPDU.add(variableBinding);
        }
        return this.snmp.get(this.scopedPDU,this.userTarget);
    }

    public ResponseEvent snmpSet(List<VariableBinding> variableBindingList ) throws IOException {
        scopedPDU.clear();
        for (VariableBinding variableBinding:variableBindingList) {
            this.scopedPDU.add(variableBinding);
        }
        return this.snmp.set(this.scopedPDU,this.userTarget);
    }
}
