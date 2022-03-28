package secureIoD;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.util.ArrayList;

/**
 * This class defines the Block object and methods for use with BlockChain.
 * @author Andrew Wall
 *
 */
public class Block {

	private int ZSP_ID;
	private int nonce;
	private byte[] hash;
	private byte[] prevHash;
	private Timestamp timestamp;
	private ArrayList<String> transactions;
	
	/**
	 * This constructor creates a Block object.
	 * @param ZSP_ID is the id of the ZSP creating the Block.
	 * @param timestamp is the time the Block is being created.
	 * @param prevHash is the hash value of the previous Block in the BlockChain.
	 * @param transactions is the data of the Block.
	 */
	public Block(int ZSP_ID, Timestamp timestamp, byte[] prevHash, ArrayList<String> transactions) {
		this.ZSP_ID = ZSP_ID;
		this.timestamp = timestamp;
		this.prevHash = prevHash;
		this.transactions = transactions;
		this.nonce = 0;
		this.hash = generateBlockHash();
	}

	/**
	 * This function generates and returns the hash value of this Block.
	 * @return the hash value of the Block.
	 */
	public byte[] generateBlockHash() {
		try {
			String toHash = "" + ZSP_ID + timestamp.toString() + Integer.toString(nonce) + prevHash + transactions.toString();
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] mdBytes = md.digest(toHash.getBytes(StandardCharsets.UTF_8));
			
			return mdBytes;
	
		} catch (Exception e) {
			// TODO: handle exception
			throw new RuntimeException();
		}
	}

	public int getZSP_ID() {
		return ZSP_ID;
	}
	
	public void setNonce(int nonce) {
		this.nonce = nonce;
	}

	public int getNonce() {
		return nonce;
	}
	
	public void setHash() {
		hash = generateBlockHash();
	}
	
	public byte[] getHash() {
		return hash;
	}

	public byte[] getPrevHash() {
		return prevHash;
	}

	public Timestamp getTimestamp() {
		return timestamp;
	}

	public ArrayList<String> getTransactions() {
		return transactions;
	}
	
	public int getTransactionsNumber() {
		return transactions.size();
	}
}
