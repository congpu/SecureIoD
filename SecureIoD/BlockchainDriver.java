package secureIoD;

public class BlockchainDriver {

	public static int iterations = 1;
	public static int transactions = 10;
	
	public static void main(String[] args) {
		
		ZSP zsp = new ZSP(1);
		int difficulty = 3;
		
		for (int i = 0; i < iterations; i++) {
			for (int j = -1; j < transactions; j++) {
				zsp.collectData("Test Data");
			}
			
			System.out.println("Data waiting to be stored in the blockchain: " + zsp.getTransactions());
			
			zsp.storeData(difficulty);
		}
		
		System.out.println("Blockchain: " + zsp.getChain());
	}
	
	// Estimated runtime resource: https://bitcoin.stackexchange.com/questions/81655/creating-a-hash-that-starts-wtih-9-zeros
	// Estimated energy consumption resource: https://stackoverflow.com/questions/1998778/how-to-measure-the-power-consumed-by-a-c-algorithm-while-running-on-a-pentium-4/2000915
}
