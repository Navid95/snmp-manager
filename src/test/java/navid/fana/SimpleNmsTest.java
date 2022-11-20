package navid.fana;

import navid.fana.nms.SimpleNms;
import org.junit.Test;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.smi.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class SimpleNmsTest {
    String hostIP = "127.0.0.1";
    String hostPort = "161";
    String username = "snmpuser";
    String password = "1qaz2wsx";
    String privateKey = "2wsx3edc";
    Address address = new UdpAddress(hostIP + "/" + hostPort);
    OID getOid = new OID("1.3.6.1.2.1.1.4.0");
//    OID getOid = new OID(".1.3.6.1.2.1.1.1.0");

    /* snmpget -v 2c -c public -On 127.0.0.1:161 sysContact.0
       .1.3.6.1.2.1.1.4.0 = STRING: navid.mhkh@gmail.com
    */
    OID setOid = new OID(".1.3.6.1.2.1.1.4.0");
    String setOidValue = "Behzad";

    @Test
    public void testGet(){

        List<OID> oidList = new ArrayList<>();
        oidList.add(getOid);
        ResponseEvent responseEvent;
        try {
            SimpleNms simpleNms = new SimpleNms();
            simpleNms.init(address,username,password,privateKey);
            responseEvent = simpleNms.snmpGet(oidList);
            assertNotNull(responseEvent);
            System.out.println("responseEvent:\t"+responseEvent);
            assertNotNull(responseEvent.getRequest());
//            System.out.println("responseEvent.getRequest(): \t"+responseEvent.getRequest());
//            assertNot(responseEvent.getError());
            System.out.println("responseEvent.getError(): \t"+responseEvent.getError());
            assertNotNull(responseEvent.getResponse());
            System.out.println("responseEvent.getResponse(): \t"+responseEvent.getResponse());

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testSet() {

        List<VariableBinding> variableBindingList = new ArrayList<>();
        ResponseEvent responseEvent;
        try {
            variableBindingList.add(new VariableBinding(setOid, new OctetString(setOidValue)));
            SimpleNms simpleNms = new SimpleNms();
            simpleNms.init(address,username,password,privateKey);
            responseEvent = simpleNms.snmpSet(variableBindingList);
            assertNotNull(responseEvent);
            System.out.println("responseEvent:\t"+responseEvent);
            assertNotNull(responseEvent.getRequest());
            System.out.println("responseEvent.getRequest(): \t"+responseEvent.getRequest());
            assertNull(responseEvent.getError());
            System.out.println("responseEvent.getError(): \t"+responseEvent.getError());
            assertNotNull(responseEvent.getResponse());
            System.out.println("responseEvent.getResponse(): \t"+responseEvent.getResponse());
            assertEquals(0,responseEvent.getResponse().getErrorStatus());
            System.out.println("responseEvent.getResponse().getErrorStatus(): \t"+responseEvent.getResponse().getErrorStatus());
            assertEquals(new OctetString(setOidValue),responseEvent.getResponse().getVariable(setOid));
            System.out.println("setOidValue: \t"+new OctetString(setOidValue)+"\nresponseEvent.getResponse().getVariable(setOid): \t"+responseEvent.getResponse().getVariable(setOid));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
