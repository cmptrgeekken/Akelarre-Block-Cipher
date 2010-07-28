package Akelarre;
import java.util.Random;

/**
 * Performs an encryption or decryption operation.
 *
 */
public class Akelarre {

	/**
	 * The default key size. It should be in increments of 64 bits then
	 * divided by 8 for the number of bytes.
	 */
	public static final int DEFAULT_KEY_SIZE = 64/8;

	/**
	 * The default number of rounds to run.
	 */
	public static final int DEFAULT_NUM_ROUNDS = 4;

	/**
	 * The number of rounds to run.
	 */
	public int num_rounds;

	/**
	 * A bitmask constant that is used frequently.
	 */
	private static final int LAST_7_BITS = 0x0000007F;

	/**
	 * An instance of the key scheduler.
	 */
	private KeyScheduler scheduler;


	/**
	 * A variable for defining if rotations should take place.
	 */
	public boolean doRotate = false;

	/**
	 * Encryption keys
	 */
	private int[] Z;

	/**
	 * Decryption keys
	 */
	private int[] D;

	
	public static int[] hexStringToIntegerArray(String hexString) {
		int[] k = new int[hexString.length() / 8];
		int ct = 0;

		for(int i = 0;i < hexString.length(); i += 8) {
			int piece = 0;
			for(int j = 0; j < 8; ++j) {
				piece |= Integer.parseInt("" + hexString.charAt(i + j), 16) << 28 - (j * 4);
			}
			
			k[ct++] = piece;
		}

		return k;
	}
	
	/**
	 * A simple method that encrypts all zeros with a random key, then decrypts
	 * the cipher text and displays the results.
	 */
	public static void main(String[] args) {
		// check for improper usage
		if (args.length < 2) {
			System.out.println("Usage: Akelarre encrypt|decrypt <text> [key]");
			return;
		}
		
		
		Random r = new Random();
		int[] result = {0};
		
		// get command line parameters
		String action = args[0];
		int[] text   = Akelarre.hexStringToIntegerArray(args[1]);
		
		// Cannot decrypt without a key
		if (!action.equalsIgnoreCase("encrypt") && args.length < 3) {
			System.out.println("Usage: Akelarre decrypt <text> <key>");
			return;
		}
		
		// Generate a random key for starters.  This will be replaced
		// if a key was passed on the command line.
		int[] key = {r.nextInt(), r.nextInt(), r.nextInt(), r.nextInt()};
		
		
		// get the key if it was given
		if (args.length >= 3) {
			key = Akelarre.hexStringToIntegerArray(args[2]);
		}
		
		// the cipher to use to encrypt and decrypt
		Akelarre cipher = new Akelarre(1, key.length * 4, key);
		
		// perform action
		if (action.equalsIgnoreCase("encrypt")) {
			result = cipher.encrypt(text);
		}
		else { // decrypt
			result = cipher.decrypt(text);
		}
		
		
		// display the result
		System.out.println("key:     " + Akelarre.toHexString(key));
		System.out.println("output:  " + Akelarre.toHexString(result));
	}


	/**
	 * A helper function to print out integer arrays as hex strings.
	 *
	 * @param ints The integers to print.
	 */
	public static void printText( int[] ints){
		for( int c : ints){
			System.out.print(" " + Integer.toHexString(c).toUpperCase());
		}
	}
	
	/**
	 * A helper function to convert integer arrays to hex strings.
	 *
	 * @param ints The integers to print.
	 */
	public static String toHexString( int[] ints){
		String result = "";
		
		for( int c : ints){
			result += " " + Integer.toHexString(c).toUpperCase();
		}
		
		return result;
	}

	/**
	 * Generate random keys.
	 *
	 * @param size The size of the key to generate.
	 * @param mask The number of bits that will be used in the key.
	 * @return A random key of the specified size.
	 */
	private static int[] gen_random_key(int size,int mask){
		int[] key = new int[size/4];
		Random rand = new Random(42);
		for(int i=0;i<key.length;i++){
			key[i] = rand.nextInt() & (mask-1);
		}

		System.out.println("Key: " + Integer.toHexString(key[0]));

		return key;
	}

	/**
	 * A constructor that generates a random key of size mask.
	 *
	 * @param mask The number of bits in the key that will be used.
	 */
	public Akelarre(int mask){
		this(DEFAULT_NUM_ROUNDS,4,gen_random_key(4,mask));
	}


	/**
	 * Constructs the akelarre with a key specified as an array of ints.
	 *
	 * @param key The key
	 */
	public Akelarre(int[] key){
		this(DEFAULT_NUM_ROUNDS,DEFAULT_KEY_SIZE,key);
	}

	/**
	 * Constructs the akelarre cipher with a number of rounds, key size,
	 * and a specified key.
	 *
	 * @param num_rounds	Number of rounds
	 * @param key_size		Key size
	 * @param key			The encryption key
	 */
	public Akelarre(int num_rounds,int key_size,int[] key){
		this.num_rounds = num_rounds;
		scheduler = new KeyScheduler(num_rounds,key_size);
		Z = scheduler.schedule(key);
		D = scheduler.createDecryptionSubkeys(Z);
	}

	/**
	 * Encrypts the plain text and returns cipher text.
	 *
	 * @param plaintext The plaintext.
	 * @return	Cipher text.
	 */
	public int[] encrypt( int[] plaintext ){
        if( plaintext.length != 4 ){
			throw new IllegalArgumentException();
		}
		return encrypt(plaintext.clone(),Z);
	}

	/**
	 * Decrypts the ciphertext and returns plaintext.
	 *
	 * @param cipherText The cipherText
	 * @return plain text
	 */
	public int[] decrypt( int[] cipherText ){
		return encrypt(cipherText.clone(),D);
	}

	/**
	 * Encrypt the specified plaintext using the given key.
	 * Plaintext must be 128 bits (16 bytes) in length, and
	 * the key must be KEY_SIZE bits in length.
	 *
	 * Based on the Schnier paper
	 */
	public int[] encrypt( int[] a, int[] k){


		//int[] a = plaintext;

		//Initialization
		a[0] += k[0];
		a[1] ^= k[1];
		a[2] ^= k[2];
		a[3] += k[3];

        int P1, P2, t0, t1;
		//Begin Rounds
		for( int r=0; r < num_rounds; r++){

			//Step 1,2,3

			if( doRotate )
				rotl128(a,  k[13*r+4] & LAST_7_BITS);//Z[num_rounds+1][0] & LAST_7_BITS);

			//Step 4
			P1 = a[0] ^ a[2]; //W0
			P2 = a[1] ^ a[3]; //W1

			t1 = rotl31(P1,P2&0x1f);
			t1+= k[13*r+5];
			t1 = rotl1(t1,(P1>>>5)&0x1f);
			t1+= k[13*r+6];
			t1 = rotl31(t1,(P1>>>10) &0x1f);
			t1+= k[13*r+7];
			t1 = rotl1(t1,(P1>>>15) &0x1f);
			t1+= k[13*r+8];
			t1 = rotl31(t1,(P1>>>20)&0xf);
			t1+= k[13*r+9];
			t1 = rotl1(t1,(P1>>>24)&0xf);
			t1+= k[13*r+10];

			t0 = rotl1(t1,P1&0x1f);
			t0+= k[13*r+11];
			t0 = rotl31(t0,(P1>>>5)&0x1f);
			t0+= k[13*r+12];
			t0 = rotl1(t0,(P1>>>10)&0x1f);
			t0+= k[13*r+13];
			t0 = rotl31(t0,(P1>>>15)&0x1f);
			t0+= k[13*r+14];
			t0 = rotl1(t0,(P1>>>20)&0xf);
			t0+= k[13*r+15];
			t0 = rotl31(t0,(P1>>>24)&0xf);
			t0+= k[13*r+16];


			//Step 6
			a[0] ^=t1;
			a[2] ^=t1;
			a[1] ^=t0;
			a[3] ^=t0;

			//End Rounds
		}

		//Output Transformation
		//Step 1,2,3

		if( doRotate )
			rotl128(a,  k[13*num_rounds+4] & LAST_7_BITS);

		//Step 4
		a[0] = a[0]+k[13*num_rounds+5];
		a[1] = a[1]^k[13*num_rounds+6];
		a[2] = a[2]^k[13*num_rounds+7];
		a[3] = a[3]+k[13*num_rounds+8];

		//Step 5
		return a;
	}


	/**
	 * From Schneier's implementation:
	 * rotate left the 31 most significant bits
	 */
	public static int rotl31( int x, int y )
	{
		int bit = x & 0x1;
		x &= 0xfffffffe;
		return ((x<<y) | (x>>>(31-y)))|bit;
	}

	/**
	 * From Schneier's implementation:
	 * rotate left the 31 less significant bits
	 */
	public static int rotl1( int x, int y )
	{
		int bit = x & 0x80000000;
		x &= 0x7fffffff;
		return ((x<<y) | (x>>>(31-y)))|bit;
	}

	/**
	 * Rotate left a 128bit integer array.
	 *
	 * @param input The array to rotate
	 * @param amount The amount to rotate by.
	 */
	public static void rotl128(int[] input, int amount){
		int shiftAmount = amount % 128;
		int overflow = 0;

		while( amount > 0 ){
			shiftAmount = amount;
			if( shiftAmount > 31 ){
				shiftAmount = 31;
			}

			overflow = (input[0] >>> (32-shiftAmount));
			for( int i=0; i < input.length-1; i++){
				input[i] = (input[i]<<shiftAmount) | (input[i+1] >>> (32-shiftAmount));
			}
			input[input.length-1] = (input[input.length-1]<<shiftAmount) | overflow;

			amount -= shiftAmount;
		}
    }

	/**
	 * Function used for debugging purporses. It returns a string of 0's and 1's
	 * from the input integer without truncating leadings zeros.
	 *
	 * @param input An integer to convert to a binary string.
	 * @return A binary string representation.
	 */
	public static String getBytes(int input){
		StringBuilder build = new StringBuilder(32);
		build.append(input<0?"1":"0");
		for( int i=30;i>=0;i--){
			boolean match = (input & (1 << i)) > 0;
			build.append(match?"1":"0");
		}

		return build.toString();
	}

	/**
	 * Another helper function for debugging purposes. This converts the
	 * binary input string and returns an integer array.
	 *
	 * @param input The input string
	 * @return An integer array.
	 */
	public static int[] bytesToInt(String input){
		int[] ints = new int[input.length() / 32];
		for(int i=0;i<ints.length;i++){
			ints[i] = 0;
			for(int j=0;j<32;j++){
				ints[i] |= ((input.charAt(32*i+j) == '1'?1:0) << (31-j));
			}
		}
		return ints;
	}
}
