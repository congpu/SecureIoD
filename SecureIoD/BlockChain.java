package secureIoD;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;

/**
 * This class defines the BlockChain object and methods to be used by ZSP.
 * @author Andrew Wall
 *
 */
public class BlockChain {

	private Date date;
	private Timestamp timestamp;
	private ArrayList<Block> blockchain;
	private Random rand;
	private int N_stake;
	private int N_trans;
	private byte[] hashThreshold;
	
	/**
	 * This constructor creates the BlockChain object and adds the Genesis Block.
	 * @param ZSP_ID
	 */
	public BlockChain(int ZSP_ID) {
		date = new Date();
		timestamp = new Timestamp(date.getTime());
		rand = new Random();
		blockchain = new ArrayList<Block>();
		blockchain.add(generateGenesisBlock(ZSP_ID));
	}
	
	/**
	 * This function creates and returns the Genesis Block.
	 * @param ZSP_ID
	 * @return
	 */
	public Block generateGenesisBlock(int ZSP_ID) {
		ArrayList<String> genesis = new ArrayList<String>();
		genesis.add("Genesis Block");
		return new Block(ZSP_ID, timestamp, new byte[] {0}, genesis);
	}
	
	/**
	 * This function takes a Block and difficulty level (1-3), finds the Block hash that matches the hash threshold, then adds the Block to the BlockChain.
	 * @param block
	 * @param difficulty
	 */
	public void addBlock(Block block, int difficulty) {
		// By default, the values are set to difficulty 1.
		double a = 1.13;
		double b = 0.125;
		int c = 20;
		
		// The variable b is unchanged for each difficulty level.
		if (difficulty == 2) {
			a = 0.93; c = 15;
		}
		if (difficulty == 3) {
			a = 0.53; c = 10;
		}
		
		N_trans = block.getTransactionsNumber();
		N_stake = (int)(c + (a * Math.exp(N_trans * b)));
		if (N_stake > block.getHash().length) {
			N_stake = block.getHash().length - 1;
		}
		
		hashThreshold = new byte[block.getHash().length]; 
		byte[] zeros = zeros(N_stake);
		byte[] randomThreshold = new byte[block.getHash().length - N_stake - 1];
		rand.nextBytes(randomThreshold);
		System.arraycopy(zeros, 0, hashThreshold, 0, zeros.length);
		System.arraycopy(randomThreshold, 0, hashThreshold, zeros.length, randomThreshold.length);
		
		boolean greater = true;
		while (greater) {
			for (int i = 0; i < hashThreshold.length; i++) {
				if (block.getHash()[i] < hashThreshold[i]) {
					block.setNonce(block.getNonce() + 1);
					block.setHash();
					i = hashThreshold.length;
					greater = true;
				} else {
					greater = false;
				}
			}
		}
		blockchain.add(block);
	}
	
	/**
	 * This function takes the N_stake variable and returns a byte array of zeros equal to the N_stake value.
	 * @param value
	 * @return
	 */
	private byte[] zeros(int value) {
		// TODO Auto-generated method stub
		byte[] zeros = new byte[value];
		for (int i = 0; i < value; i++) {
			zeros[i] = 0;
		}
		return zeros;
	}

	/**
	 * This function returns the list of Blocks stored in this BlockChain.
	 * @return
	 */
	public ArrayList<Block> getBlockChain() {
		return blockchain;
	}
	
	/**
	 * This function returns the last Block that was added to the BlockChain.
	 * @return
	 */
	public Block getLatestBlock() {
		return blockchain.get(blockchain.size() - 1);
	}
	
	/**
	 * This function checks the integrity of the BlockChain by checking each Block's stored hash with its generated hash and 
	 * each Block's hash with the next Block's prevHash stored variable.
	 * @return true if the BlockChain finds no inconsistencies, false if BlockChain finds inconsistencies.
	 */
	public Boolean checkIntegrity() {
		for (int i = 1; i < blockchain.size(); i++) {
			if (!blockchain.get(i).getHash().equals(blockchain.get(i).generateBlockHash())) {
				return false;
			}
			if (!blockchain.get(i).getPrevHash().equals(blockchain.get(i-1).getHash())) {
				return false;
			}
		}
		return true;
	}
}
