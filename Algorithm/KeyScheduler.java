package Akelarre;

public class KeyScheduler {
	private final int NUM_ROUNDS;
	public final int KEY_SIZE; // Key size in bytes
	private final int A0 = 0xA49ED284;
	private final int A1 = 0x735203DE;

	/**
	 * Constructor for the Key Scheduler
	 *
	 * Sample Usage:
	 * KeyScheduler scheduler = new KeyScheduler(4,128);
	 * scheduler.schedule("BjamHBhn@KQnhElx");
	 *
	 * @param num_rounds Number of rounds Akelarre will perform
	 * @param key_size Size of the key in bytes
	 */
	public KeyScheduler(int num_rounds,int key_size){
		NUM_ROUNDS = num_rounds;
		KEY_SIZE = key_size;
	}


	/**
	 * Scheduling routine. Accepts a key of KEY_LENGTH bytes and
	 * generates 13*NUM_ROUNDS+9 subkeys based off that key.
	 *
	 * @param key key to use for calculating the subkeys
	 * @return array of subkeys
	 */
	public int[] schedule(int[] key){
		//int[][] K = new int[NUM_ROUNDS+2][13];
		int[] K = new int[13*NUM_ROUNDS+9];

		if( key.length != KEY_SIZE/4){
			throw new IllegalArgumentException("Key provided of improper length.");
		}

		// Generate key.length*2 subblocks for
		// use in the routine. These subblocks are formed
		// by splitting each int in the key into two
		// shorts
		int[] s = new int[key.length*2];
		int[] u = new int[key.length*2];
		int[] v = new int[key.length*2];
		for(int i=0;i<s.length;i+=2){
			s[i]     = key[i/2] >>> 16;
			s[i+1]   = key[i/2] & 0xFFFF;

			u[i]     = (s[i]*s[i]+A0);
			v[i]     = (s[i]*s[i]+A1);
			u[i+1]   = (s[i+1]*s[i+1]+A0);
			v[i+1]   = (s[i+1]*s[i+1]+A1);
		}


		/*
		 * Scheduling algorithm
		 */
		for(int i=0;i<13*NUM_ROUNDS+9;i++){
			int index = i % s.length;
			int um = (u[index] >> 8) & 0xFFFF;
			int vm = (v[index] >> 8) & 0xFFFF;
			// Key:
			// - Take outermost bytes of kl and swap them
			// - Set the two most significant bytes of the key to those bytes
			// - Take outermost bytes of kr and swap them
			// - Set two least significant bytes of the key to those bytes
			K[i] = ((u[index] << 24) & 0xFF000000) | ((u[index] >> 8) & 0xFF0000)  | ((v[index] << 8) & 0xFF00) | ((v[index] >> 24) & 0xFF);

			// Set left subblock to its middle 16 bits.

			u[index] = um*um+A0;
			v[index] = vm*vm+A1;
		}
		return K;
	}

	/**
	 * A function that performs a negation on the last 8 bits.
	 * @param A
	 * @return
	 */
	public static int neg(int A){
		int x = A&0x7f;
		int y = (-(x % 128));
		return (A & 0xFFFFFF80) | (y&0x7f);
	}

	/**
	 * Creates decryption sub-keys from encryption sub-keys.
	 *
	 * @param Z	The encryption sub-keys.
	 * @return Decryption sub-keys
	 */
	public int[] createDecryptionSubkeys(int[] Z){
		int[] D = new int[13*NUM_ROUNDS+9];
		D[0] = -Z[13*NUM_ROUNDS+5];
		D[1] =  Z[13*NUM_ROUNDS+6];
		D[2] =  Z[13*NUM_ROUNDS+7];
		D[3] = -Z[13*NUM_ROUNDS+8];

		for(int r=0;r<=NUM_ROUNDS-1;r++){
			D[13*r+4] = neg(Z[13*(NUM_ROUNDS-r)+4]);
			for( int j=5;j<=16;j++ ){
				D[13*r+j] = Z[13*(NUM_ROUNDS-r-1)+j];
			}
		}

		D[13*NUM_ROUNDS+4] = neg(Z[4]);

		D[13*NUM_ROUNDS+5] = -Z[0];
		D[13*NUM_ROUNDS+6] =  Z[1];
		D[13*NUM_ROUNDS+7] =  Z[2];
		D[13*NUM_ROUNDS+8] = -Z[3];
		return D;
	}
}
