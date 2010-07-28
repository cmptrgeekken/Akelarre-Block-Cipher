package Coconut;

import java.util.ArrayList;
import java.util.Random;

import Akelarre.Akelarre;

/*
 * Performs a bit by bit attack without backtracking or carry.
 */
public class BitAttack {
	int[][] X,Y;
	public static final int NUM_PLAINTEXTS = 5;

	public static void main(String[] args){
		int[][] X = {
				{0x53,0x8d,0x86,0x80},
				{0x21,0x32,0xf0,0x7f},
				{0x54,0x77,0xd5,0x2b},
				{0xea,0x75,0xaa,0xd3},
				{0x27,0x95,0xb7,0x2d}};
		int[][] Y = {
				{0x74,0x21,0x9c,0x0a},
				{0x75,0xb9,0x3f,0xf0},
				{0xf7,0x92,0x4d,0xee},
				{0x39,0x1f,0x22,0x1b},
				{0x19,0xbc,0xa2,0xc0}};

		Random rand = new Random();
		Akelarre ake = new Akelarre(1,8,new int[]{0,0});
		String alpha = "abcdefghijklmnopqrstuvwxyz";
		X = new int[NUM_PLAINTEXTS][4];
		for(int i=0;i<X.length;i++){
			for(int j=0;j<X[i].length;j++){
				for(int k=0;k<4;k++){
					byte n = (byte)alpha.charAt(rand.nextInt(alpha.length()));
					X[i][j] |= (n << 8*k);
				}
			}
			//X[i] = new int[]{alpha.charAt(rand.nextInt()%alpha.length()),rand.nextInt(),rand.nextInt(),rand.nextInt()};
			Y[i] = ake.encrypt(X[i]);
		}


		//int[] aecXORg = attack(ae,getCG);

	}

	/*
	 * Tests for the equation ae
	 */
	TestFunction ae = new TestFunction(){
		public boolean test(int a,int e,int[] xl, int[] xr, int[] yl, int[] yr,int mask){
			// (x0+a)^(y0-e)^x2^y2 == (x0+a)^(y0-e)^x2^y2
			return ((((xl[0]+a)^(xr[0]+a)^(yl[0]-e)^(yr[0]-e))&mask) == ((xl[2]^xr[2]^yl[2]^yr[2])&mask));
		}
	};


	/*
	 * Tests for CG
	 */
	GetXOR getCG = new GetXOR(){
		public int get(int a,int e){
			return ((X[0][0]+a)^(Y[0][0]-e)^X[0][2]^Y[0][2]);
		}
	};

	/*
	 * Tests for equation x02.
	 */
	static TestPlaintext x02 = new TestPlaintext(){
		public boolean test(int x0,int x2,int[] Y,int a,int e,int cXORg,int mask){
			return (((x0+a)^x2)&mask)==(((Y[0]-e)^Y[2]^cXORg)&mask);
		}
	};

	/*
	 * Test for x13
	 */
	static TestPlaintext x13 = new TestPlaintext(){
		public boolean test(int x1,int x3,int[] Y,int d,int h,int bXORf,int mask){
			return (((x3+d)^x1)&mask)==(((Y[3]-h)^Y[1]^bXORf)&mask);
		}
	};

	/*
	 * Constructs the bit attack.
	 */
	public BitAttack(int[][] X,int[][] Y){
		this.X = X;this.Y=Y;
	}

	/*
	 * Perform the attack.
	 */
	public ArrayList<int[]> attack(){return attack(8);}
	public ArrayList<int[]> attack(int numBits){return attack(ae,getCG,numBits);}
	public ArrayList<int[]> attack(TestFunction t1,GetXOR getXor,int numBits){
		int mask = 1;

		ArrayList<int[]> pairs = new ArrayList<int[]>();
		pairs.add(new int[]{0,0});

		for( int i=0;i<numBits;i++){
			for( int j=0;j<X.length-1;j++ ){
				int[] xl = X[j],xr = X[j+1];
				int[] yl = Y[j],yr = Y[j+1];

				mask |= (1 << i);
				ArrayList<int[]> curPairs = new ArrayList<int[]>();
				ArrayList<int[]> innerPairs = new ArrayList<int[]>();
				for(int[] pair : pairs ){
					if( j == 0 ){
						for( int l=0;l<4;l++ ){
							int a=pair[0];int b=pair[1];
							switch(l){
								case 1:
									b |= (1 << i);
									break;
								case 2:
									a |= (1 << i);
									break;
								case 3:
									a |= (1 << i);
									b |= (1 << i);
									break;
							}
							innerPairs.add(new int[]{a,b});
						}
					}else{
						innerPairs.add(pair);
					}
				}

				for(int[] pair : innerPairs){
					int a=pair[0],b=pair[1];
					if( t1.test(a,b,xl,xr,yl,yr,mask) ){
						int[] p1 = new int[]{a,b};
						boolean match = false;
						for( int[] p2 : curPairs ){
							if( p1[0] == p2[0] && p1[1] == p2[1] ){
								match = true;
							}
						}

						if( !match){
							curPairs.add(p1);
						}
					}
				}

				pairs = new ArrayList<int[]>(curPairs);
			}
		}

		if( pairs.size() == 0 ){
			return null;
		}

		for(int[] pair : pairs){
			pair = new int[]{pair[0],pair[1],getXor.get(pair[0],pair[1])};
		}


		return pairs;
	}

	/*
	 * Interface for a test function
	 */
	interface TestFunction{
		public boolean test(int a,int b,int[] x0, int[] x1, int[] y0, int[] y1,int mask);
	}

	/*
	 * Interface for a plaintext test
	 */
	interface TestPlaintext{
		public boolean test(int x0,int x1,int[] Y,int a,int b,int cXORg,int mask);
	}

	/*
	 * Interface for a getXor function type.
	 */
	interface GetXOR{
		public int get(int a,int e);
	}
}

