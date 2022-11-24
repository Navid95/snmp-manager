package navid.fana;

import navid.fana.nms.SimpleNms;
import org.snmp4j.PDU;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.smi.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Run {

    public static void main(String[] args){

        try {
            SimpleNms simpleNms = new SimpleNms();
            String privateKey;
            String hostIP;
            String hostPort;
            String username;
            String password;
            Scanner scanner;
            String hostAddress;
            Address address;
            scanner = new Scanner(System.in);

//          Getting initial user inputs
            System.out.println("Enter snmp host IP address:");
            hostIP = scanner.next();
            System.out.println("Enter snmp host port:");
            hostPort = scanner.next();
            System.out.println("Enter snmp username:");
            username = scanner.next();
            System.out.println("Enter snmp password:");
            password = scanner.next();
            System.out.println("Enter snmp private key:");
            privateKey = scanner.next();

//            initialize the SNMP NMS
            hostAddress = hostIP + "/" + hostPort;
            address = new UdpAddress(hostAddress);
            simpleNms.init(address, username, password, privateKey);

//            Menu
            menu(scanner, simpleNms);


        } catch (IOException e) {
            System.out.println("NMS initialization failed.");

            e.printStackTrace();
        }
    }

    public static void menu(Scanner scanner, SimpleNms simpleNms){
        int menu1Choice = 0;
        final int subMenu1Exit = -1;
        String oid;
        String setVariableValue = "";
        printMenu();
        menu1Choice = scanner.nextInt();
        switch (menu1Choice){
            case 1:
                System.out.println("Enter OID:");
                oid = scanner.next();
                List<OID> oidList = new ArrayList<>();
                oidList.add(new OID(oid));
                try {
                    ResponseEvent responseEvent = simpleNms.snmpGet(oidList);
                    if (responseEvent != null) {
                        if (responseEvent.getResponse() != null) {
                            if (responseEvent.getResponse().getErrorStatusText().equalsIgnoreCase("success")) {
                                PDU responsePDU = responseEvent.getResponse();
                                System.out.println("\nsnmp GET response:\n" + responsePDU.getVariableBindings().get(0));
                            } else {
                                System.out.println("snmp GET request is null.\n Printing the response:\n\t" + responseEvent.getResponse());
                            }
                        } else {
                            System.out.println("snmp GET request time out.");
                        }
                    } else {
                        System.out.println("snmp GET request time out.");
                    }
                } catch (IOException e) {
                    System.out.println("Problem in sending the snmp get request");
                    e.printStackTrace();
                } menu(scanner, simpleNms);
                break;

            case 2:
                System.out.println("Enter OID:");
                oid = scanner.next();
                System.out.println("Enter OID Value:");
                setVariableValue = scanner.next();
                List<VariableBinding> variableBindingList = new ArrayList<>();
                variableBindingList.add(new VariableBinding(new OID(oid),new OctetString(setVariableValue)));
                try {
                    ResponseEvent responseEvent = simpleNms.snmpSet(variableBindingList);
                    if (responseEvent != null) {
                        if (responseEvent.getResponse().getErrorStatusText().equalsIgnoreCase("success") && responseEvent.getResponse().getErrorStatus() == 0) {
                            PDU responsePDU = responseEvent.getResponse();
                            System.out.println("\nsnmp SET response:\n" + responsePDU.getVariableBindings().get(0));
                        } else {
                            System.out.println("snmp SET response is null.\nResponse:\n\t" + responseEvent.getResponse());
                            System.out.println("Error:\n\t" + responseEvent.getResponse().getErrorStatus());
                            System.out.println("Error description:\n\t" + responseEvent.getResponse().getErrorStatusText());
                        }
                    } else {
                        System.out.println("snmp SET request time oue.");
                    }
                } catch (IOException e) {
                    System.out.println("Problem in sending the snmp SET request");
                    e.printStackTrace();
                } menu(scanner,simpleNms);
                break;

            case subMenu1Exit:
                break;

            default:menu(scanner,simpleNms);
        }
        System.exit(0);
    }

    public static void printMenu() {
        System.out.println("\nEnter the operation you desire(number):\n1) send snmp GET request.\n2) send snmp SET request.\n-1) to exit the program.\n");
    }

    public static void clearScreen() {
        try {
            final String os = System.getProperty("os.name");
            if (os.contains("Windows")) {
                Runtime.getRuntime().exec("cls");
            } else {
                Runtime.getRuntime().exec("clear");
                }
        }
        catch (final Exception e) {
            e.printStackTrace();
        }
    }
}
