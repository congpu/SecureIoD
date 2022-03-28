package secureIoD;

/**
 * The Entry class is used for the drone database entries stored on the ground station.
 * @author Andrew Wall
 *
 */
public class Entry {
	
	private int pid;
	private int id;
	private double challenge;
	private double response;
	
	/**
	 * This constructor is used to make a new entry
	 * @param initial_pid is the pseudonym used by the drone.
	 * @param id is the drone's id number.
	 * @param initial_challenge is the challenge used for authenticating the drone with the ground station.
	 * @param initial_response is the response used for authenticating the drone with the ground station.
	 */
	public Entry(int initial_pid, int id, double initial_challenge, double initial_response) {
		// TODO Auto-generated constructor stub
		pid = initial_pid;
		this.id = id;
		challenge = initial_challenge;
		response = initial_response;
	}
	
	public int getPid() {
		return pid;
	}

	public void setPid(int pid) {
		this.pid = pid;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public double getChallenge() {
		return challenge;
	}

	public void setChallenge(double challenge) {
		this.challenge = challenge;
	}

	public double getResponse() {
		return response;
	}

	public void setResponse(double response) {
		this.response = response;
	}

}
