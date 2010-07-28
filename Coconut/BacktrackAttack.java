package Coconut;

import java.util.ArrayList;
import java.util.Random;

import Akelarre.Akelarre;

/**
 * An attack that utilizes backtracking and carry bits.
 */
public class BacktrackAttack {
	public int[][] X,Y;
	private int numBits = 31;

	/**
	 * Shift the input right by a specified amount then & the input with 1.
	 */
	public static final int sA1(int in,int shift){
		return (in >>> shift) & 1;
	}

	/*
	 * A test function that includes carry bits.
	 */
	public boolean testWithCarry(Choice choice,int[] xl,int[] xr,int[] yl,int[] yr){
		int[] set = choice.set;
		int s/*hift*/ = choice.shift;
		if( s < 32 ){
			if( s == 0 ){
				int yl00 = yl[0]&1;
				int yl20 = yl[2]&1;
				int xl00 = xl[0]&1;
				int xl20 = xl[2]&1;

				int yr00 = yr[0]&1;
				int yr20 = yr[2]&1;
				int xr00 = xr[0]&1;
				int xr20 = xr[2]&1;

				int a0  = set[0]&1;
				int e0  = (-set[1])&1;

				return ((yl00^e0^xl00^a0^xl20^yl20) == (yr00^e0^xr00^a0^xr20^yr20));
			}else{
				int yl0i = sA1(yl[0],s);
				int yl2i = sA1(yl[2],s);
				int xl0i = sA1(xl[0],s);
				int xl2i = sA1(xl[2],s);
				int yl00 = sA1(yl[0],s-1);
				int xl00 = sA1(xl[0],s-1);

				int yr0i = sA1(yr[0],s);
				int yr2i = sA1(yr[2],s);
				int xr0i = sA1(xr[0],s);
				int xr2i = sA1(xr[2],s);
				int yr00 = sA1(yr[0],s-1);
				int xr00 = sA1(xr[0],s-1);

				int ai = sA1(set[0],s);
				int a0 = sA1(set[0],s-1);
				int ei = sA1(-set[1],s);
				int e0 = sA1(-set[1],s-1);


				return (yl0i^ei^xl0i^ai^xl2i^yl2i^(yl00*e0)^(xl00*a0)) == (yr0i^ei^xr0i^ai^xr2i^yr2i^(yr00&e0)^(xr00&a0));
			}
		}

		return false;
	}

	/*
	 * Construts the backtrack attac.
	 */
	public BacktrackAttack(int[][] X,int[][] Y,int numBits){
		this.X=X;this.Y=Y;
		this.numBits=numBits;
	}

	/*
	 * A simple main method for testing the backtracking.
	 */
	public static void main(String[] args){
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

		Random rand = new Random(42);
		String alpha = "abcdefghijklmnopqrstuvwxyz";
		Akelarre ake = new Akelarre(1,8,new int[]{0,0});

		ake.doRotate = false;

		for(int i=0;i<X.length;i++){
			for(int j=0;j<X[i].length;j++){
				for(int k=0;k<4;k++){
					byte n = (byte)alpha.charAt(rand.nextInt(alpha.length()));
					X[i][j] |= (n << 8*k);
				}
			}
			Y[i] = ake.encrypt(X[i]);
		}

		BacktrackAttack attack = new BacktrackAttack(X,Y,8);

		Choice ch = attack.solve();

		long st = System.currentTimeMillis();
		System.out.println("Key Found? " + (ch != null));
		System.out.println("Total time (ms): " +(System.currentTimeMillis() - st));
	}


	/*
	 * Return true if the problem has been solved.
	 */
	public boolean solved(Choice choice){
		return (choice.shift == numBits);
	}

	/*
	 * Solve with an empty choice
	 */
	public Choice solve(){
		return solve(new Choice());
	}

	/*
	 * Solves with a number of choices
	 */
	public Choice solve(Choice choice){
		if(solved(choice)) return choice;

		Choice result;
		Choice[] choices = choices(choice);
		for(Choice ch : choices){
			if((result = solve(ch)) != null){
				return result;
			}
		}

		return null;
	}

	/*
	 * Gives a list of all possible 'next steps' given the current step.
	 */
	public Choice[] choices(Choice choice){
		ArrayList<Choice> choices = new ArrayList<Choice>();

		int shift = choice.shift+1;
		for( int l=0;l<4;l++ ){
			Choice ch = new Choice(shift,choice.set);
			switch(l){
				case 0:
					break;
				case 1:
					ch.set[1] |= (1 << shift);
					break;
				case 2:
					ch.set[0] |= (1 << shift);
					break;
				case 3:
					ch.set[0] |= (1 << shift);
					ch.set[1] |= (1 << shift);
					break;
			}

			boolean works = true;
			for(int i=0;i<X.length-1;i++){
				if( !testWithCarry(ch,X[i],Y[i],X[i+1],Y[i+1]) ){
					works = false;
				}
			}

			if( works ){
				choices.add(ch);
			}
		}

		return choices.toArray(new Choice[choices.size()]);
	}

	/*
	 * Represents a choice.
	 */
	public class Choice {
		public int shift;
		public int[] set;

		public Choice(){
			shift=-1;set=new int[2];
		}

		public Choice(int shift,int[] set){
			this.shift = shift;this.set = set.clone();
		}
	}

}
