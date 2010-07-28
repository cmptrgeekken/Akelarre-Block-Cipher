package Coconut;

import Akelarre.Akelarre;

public class BruteforceAttack {
	private int[] plaintext;
	private int[] ciphertext;
	private int numBits = 8 ;
	/*
	 * Runs a sample bruteforce attack.
	 */
	public static void main(String[] args){
		// Creates an Akelarre instance with a randomly-generated key
		Akelarre ake = new Akelarre(0xFF);

		int[] pt = new int[]{0x1234,0x2341,0x3412,0x4123};
		int[] ct = ake.encrypt(pt);

		BruteforceAttack attack = new BruteforceAttack(pt,ct);
		int[] key;
		long st = System.currentTimeMillis();
		attack.attack();
		System.out.println("Total time (ms): " + (System.currentTimeMillis() - st));
		if( (key = attack.attack()) != null ){
			System.out.println("Attack succeeded!");
		}else{
			System.out.println("Attack failed.");
		}
	}

	/*
	 * Constructs a brutefore attack.
	 */
	public BruteforceAttack(int[] pt,int[] ct){this(pt,ct,8);}
	public BruteforceAttack(int[] pt,int[] ct,int numBits){
		this.plaintext = pt;
		this.ciphertext = ct;
		this.numBits = numBits;
	}

	/*
	 * Runs a bruteforce attack.
	 */
	public int[] attack(){
		int[] key = {0};
		Akelarre ake;
		int endVal = (int)Math.pow(2,numBits)-1;
		while(true){
			boolean reachedEnd = true;
			ake = new Akelarre(1,4,key);

			for(int i : key){
				if( i != endVal ){
					reachedEnd = false;
					break;
				}
			}

			if( reachedEnd ) return null;

			if(eq(ake.encrypt(plaintext),ciphertext)){
				return key;
			}

			for(int i=key.length-1;i>=0;i--){
				key[i]++;
				if( key[i] != 0){
					break;
				}
			}
		}
	}

	/*
	 * Check if integer array a and integer array b are equal.
	 */
	private boolean eq(int[] a,int[] b){
		boolean eq = true;
		if(a.length != b.length) return false;
		for(int i=0;i<a.length;i++){
			if( a[i] != b[i] ){
				eq = false;
				break;
			}else{

			}
		}
		return eq;
	}
}
