/**
 * This class represents a reduced-strength variant
 * of the Akelarre cipher. We're given five plaintexts
 * and five ciphertexts, each of which consist of
 * four bytes. This is a quarter of the length of the
 * full-strength Akelarre algorithm.
 *
 * The task is to recover the unknown subkeys given only
 * the plaintext and ciphertext. Here, the subkeys are
 * represented as the letters 'a' through 'h', and they
 * relate to plaintext x and ciphertext y
 * through the following equations:
 *
 * (y0-e)^y2^g = (x0+a)^x2^c
 * and
 * y1^f^(y3-h) = x1^b^(x3+d)
 *
 * In order to reduce the number of variables in the equation,
 * we solve the above equations for g^c and f^b, respectively,
 * and substitute in the values of two of the plaintext/
 * ciphertext pairs to produce two equations and two unknowns
 * for each original equation:
 *
 * g^c = (x0+a)^(y0-e)^x2^y2
 * f^b = (x3+d)^(y3-h)^x1^y1
 *
 * As a proof of concept, we will only use the first equation
 * above in this class in our recovery.
 *
 * NOTE: All numbers are hexadecimal values.
 *
 * Eq 1 (x = {53,8d,86,80} y = {74,21,9c,0a}):
 * g^c = (53+a)^(74-e)^86^9c
 *
 * Eq 2 (x = {54,77,d5,2b}, y = {f7,92,4d,ee}):
 * g^c = (54+a)^(f7-e)^d5^4d
 *
 * Given the above two equations, we can now set them equal
 * to each other, thus removing the terms g^c:
 * (53+a)^(74-e)^86^9c = (54+a)^(f7-e)^d5^4d
 *
 * Combining terms, we're left with:
 * (53+a)^(74-e)^(54+a)^(f7-e) = 82
 *
 * This program performs a brute-force attack on all possible
 * combinations of a and e, and then uses the answer to
 * determine the value of g^c. Thus, we solve the first half
 * of the original problem (the second half involves the same
 * technique applied to the second equation).
 */

package Coconut;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;

import Akelarre.Akelarre;
import Coconut.BacktrackAttack.Choice;

public class AkelarreAttacks {
	int[][] X,Y;
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Random rand = new Random();
		int numRuns = 1000;
		int numBits = 8;

		int[][] X = {
				{0x53,0x8d,0x86,0x80},
				{0x54,0x77,0xd5,0x2b},
				{0x21,0x32,0xf0,0x7f},
				{0xea,0x75,0xaa,0xd3},
				{0x27,0x95,0xb7,0x2d}};
		int[][] Y = {
				{0x74,0x21,0x9c,0x0a},
				{0xf7,0x92,0x4d,0xee},
				{0x75,0xb9,0x3f,0xf0},
				{0x39,0x1f,0x22,0x1b},
				{0x19,0xbc,0xa2,0xc0}};

		if( args.length == 2 ){
			numRuns = Integer.parseInt(args[0]);
			numBits = Integer.parseInt(args[1]);
		}else{
			System.out.println("Usage: java AkelarreAttacks <NumRuns> <NumBits>");
			System.exit(1);
		}

		int keyMask = (int)Math.pow(2, numBits)-1;

		long keyGenTime = System.currentTimeMillis();
		for(int i=0;i<numRuns;i++){
			Akelarre ake = new Akelarre(1,4,new int[]{rand.nextInt() & keyMask});
			ake.encrypt(new int[]{rand.nextInt(),rand.nextInt(),rand.nextInt(),rand.nextInt()});
		}
		keyGenTime = System.currentTimeMillis()-keyGenTime;

		AkelarreAttacks problem = new AkelarreAttacks(X,Y);
		long bfST = System.currentTimeMillis();
		for( int i=0;i<numRuns;i++ ){
			Akelarre ake = new Akelarre(1,4,new int[]{rand.nextInt() & keyMask});
			X[0] = new int[]{rand.nextInt(),rand.nextInt(),rand.nextInt(),rand.nextInt()};
			Y[0] = ake.encrypt(X[0]);
			problem.bruteforceKeyAttack(numBits);

		}

		long bfET = System.currentTimeMillis();
		System.out.println("Bruteforce Key ("+numBits+" bits)");
		System.out.println("Total time (ms): " + (bfET - bfST));
		System.out.println("Time - Key Gen Time (ms): " + (bfET - bfST - keyGenTime));
		System.out.println("Time / run (ms): " + ((double)(bfET - bfST - keyGenTime) / numRuns)+"\n");

		keyGenTime = System.currentTimeMillis();
		Akelarre ake = new Akelarre(new int[]{0,0});
		for(int i=0;i<numRuns;i++){
			for(int j=0;j<5;j++){
				X[j] = new int[]{rand.nextInt(),rand.nextInt(),rand.nextInt(),rand.nextInt()};
				Y[j] = ake.encrypt(X[j]);
			}
		}
		keyGenTime = System.currentTimeMillis() - keyGenTime;

		long bbfST = System.currentTimeMillis();
		for( int i=0;i<numRuns;i++ ){
			for(int j=0;j<5;j++){
				X[j] = new int[]{rand.nextInt(),rand.nextInt(),rand.nextInt(),rand.nextInt()};
				Y[j] = ake.encrypt(X[j]);
			}
			problem.bitSubkeyAttack(numBits);
		}
		long bbfET = System.currentTimeMillis();
		System.out.println("Bit Bruteforce ("+numBits+" bits)");
		System.out.println("Total time (ms): " + (bbfET - bbfST));
		System.out.println("Time - Key Gen Time (ms):" + (bbfET-bbfST-keyGenTime));
		System.out.println("Time / run (ms): " + ((double)(bbfET - bbfST-keyGenTime) / numRuns)+"\n");

	}

	/*
	 * Constructor that initializes some plaintext and ciphertext.
	 */
	public AkelarreAttacks(int[][] X,int[][] Y){
		this.X = X;
		this.Y = Y;
	}

	/*
	 * Runs a bruteforce key attack.
	 */
	public ArrayList<int[]> bruteforceKeyAttack(){return bruteforceKeyAttack(8);}
	public ArrayList<int[]> bruteforceKeyAttack(int numBits){
		ArrayList<int[]> values = new ArrayList<int[]>();
		int[] a = (new BruteforceAttack(X[0],Y[0],numBits)).attack();

		if( a != null ){
			values.add(a);
		}

		return values;
	}

	/*
	 * Accepts as its input an array of plaintexts (X) and
	 * an array of ciphertexts (Y) that correspond to the given
	 * plaintexts.
	 *
	 * Returns an arraylist containing all possible solutions to the
	 * problem, where each element is of the following form:
	 * {a,b,c^g}.
	 *
	 */
	public ArrayList<int[]> bruteforceSubkeyAttack(){return bruteforceSubkeyAttack(8);}
	public ArrayList<int[]> bruteforceSubkeyAttack(int numBits){
		ArrayList<int[]> vals = new ArrayList<int[]>();
		numBits = (int) Math.pow(2, numBits);
		for(int a=0;a<numBits;a++){
			for(int e=0;e<numBits;e++){
				boolean matchFound = true;
				for( int i=0;i<X.length-1;i++ ){
					int[] xl = X[i],xr = X[i+1];
					int[] yl = Y[i],yr = Y[i+1];

					// (xl0+a)^(yl0-e)^xl2^yl2 = (xr0+a)^(yr0-e)^xr2^yr2
					if( !eq423(a,e,xl,xr,yl,yr,numBits )){
						matchFound = false;
					}
				}

				if( matchFound ){
					int[] values = new int[3];

					values[0] = a;
					values[1] = e;

					// g^c = (x0+a)^(y0-e)^x2^y2
					values[2] = calcGXORC(a,e);

					vals.add(values);
				}
			}
		}

		return vals;
	}

	public ArrayList<int[]> bitSubkeyAttack(){return bitSubkeyAttack(8);}
	public ArrayList<int[]> bitSubkeyAttack(int numBits){return (new BitAttack(X,Y)).attack(numBits);}


	/*
	 * Instead of performing a full bruteforce attack, this approach performs
	 * a bruteforce attack at the bit level, looping through all current values
	 * and determining whether or not the current bit pattern satisfies the
	 * appropriate equation. This can be extended to a full-length plaintext
	 * (32 bits), but it appears as though the number of possible solutions
	 * that satisfy the equation is enormous, in many situations.
	 */
	public ArrayList<int[]> bitBruteforceSubkeyAttack(){return bitBruteforceSubkeyAttack(8);}
	public ArrayList<int[]> bitBruteforceSubkeyAttack(int numBits){
		ArrayList<int[]> values = new ArrayList<int[]>();
		values.add(new int[3]);
		for(int shift=0,mask=1;shift<numBits;shift++,mask|=(1 << shift)){
			for( int x=0;x<X.length-1;x++ ){
				int[] xl = X[x],xr = X[x+1];
				int[] yl = Y[x],yr = Y[x+1];

				ArrayList<int[]> curVals = new ArrayList<int[]>();
				HashSet<String> set = new HashSet<String>();
				if( x == 0 ){
					for(int[] val : values){
						int a = val[0],e=val[1];
						for(int i=0;i<4;i++){
							switch(i){
								case 0:
									break;
								case 1:
									e |= (1 << shift);
									break;
								case 2:
									a |= (1 << shift);
									break;
								case 3:
									a |= (1 << shift);
									e |= (1 << shift);
									break;
							}
							if( !set.contains(a+"|"+e) && eq423( a, e, xl, xr, yl, yr, mask ) ){
								curVals.add(new int[]{a,e,0});
								set.add(a+"|"+e);
							}
						}
					}
				}else{
					for(int[] val : values ){
						if( !set.contains(val[0]+"|"+val[1]) && eq423(val[0],val[1],xl,xr,yl,yr,mask) ){
							curVals.add(new int[]{val[0],val[1],0});
							set.add(val[0]+"|"+val[1]);
						}
					}
				}
				values = new ArrayList<int[]>(curVals);
			}
		}

		for(int[] val : values ){
			val[2] = calcGXORC(val[0],val[1]);
		}

		return values;
	}

	/*
	 * Attempts to run a subkey attack with backtracking.
	 */
	public ArrayList<int[]> backtrackSubkeyAttack(){return backtrackSubkeyAttack(8);}
	public ArrayList<int[]> backtrackSubkeyAttack(int numBits){
		ArrayList<int[]> vals = new ArrayList<int[]>();
		BacktrackAttack attack = new BacktrackAttack(X,Y,numBits);
		Choice ch = attack.solve();
		if( ch != null ){
			vals.add(new int[]{ch.set[0],ch.set[1],ch.set[2]});
		}
		return vals;
	}

	/*
	 * Calculate equation 4.23
	 */
	private boolean eq423(int a, int e, int[] xl, int[] xr, int[] yl, int[] yr,int mask){
		return (((xl[0]+a)^(yl[0]+(-e))^xl[2]^yl[2])&mask) == (((xr[0]+a)^(yr[0]+(-e))^xr[2]^yr[2])&mask);
	}

	/*
	 * Calculate g xor c
	 */
	private int calcGXORC(int a, int e ){
		return (X[0][0]+a)^(Y[0][0]-e)^X[0][2]^Y[0][2];
	}
}
