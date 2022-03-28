package secureIoD;

public class HenonDriver {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		int gs_id = Integer.parseInt(args[0]);
		int dr_id = Integer.parseInt(args[1]);
		int init_pid = Integer.parseInt(args[2]);
		int init_chal = Integer.parseInt(args[3]);
		int init_resp = Integer.parseInt(args[4]);
		
		int loop = 0;
		while (loop < 1) {
		
		ZSP groundStation = new ZSP(gs_id);
		Drone drone1 = new Drone(dr_id, init_pid, init_chal);
		groundStation.registerDrone(dr_id, init_pid, init_chal, init_resp);
		
		byte[][] message1 = drone1.sendMessage1(gs_id);
		System.out.println("message 1: "+ message1[0].length +" "+ message1[1].length);
		
		if(!groundStation.verifyPID(init_pid)) return;
		System.out.println("PID verified");
		groundStation.fetchEntry();
		groundStation.decryptMessage1(message1[0]);
		if (!groundStation.verifyMAC1(message1[0], message1[1])) return;
		System.out.println("MAC1 verified");
		byte[][] message2 = groundStation.sendMessage2(0);
		System.out.println("message 2: "+ message2[0].length +" "+ message2[1].length);
		
		drone1.decryptMessage2(message2[0]);
		if (!drone1.verifyMAC2(message2[0], message2[1])) return;
		System.out.println("MAC2 verified");
		drone1.generateNewCRP();
		byte[][] message34 = drone1.sendMessage34(0);
		System.out.println("message34: "+ message34[0].length +" "+ message34[1].length +" "+ message34[2].length);
		
		groundStation.decryptMessage34(message34[0], message34[1]);
		if(!groundStation.verifyMAC34(message34[0], message34[1], message34[2])) return;
		System.out.println("MAC34 verified");
		groundStation.updateEntry(init_pid);
		
		drone1.generateSessionKey();
		groundStation.generateSessionKey();	
		System.out.println("Session keys generated");
		loop++;
		System.out.println(loop);
		}
	}
}
