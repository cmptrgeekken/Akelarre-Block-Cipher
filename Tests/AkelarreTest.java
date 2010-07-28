package Tests;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import Akelarre.Akelarre;
import Akelarre.KeyScheduler;
import junit.framework.TestCase;

/**
 * This class provides a way to test individual functions in the Akelarre
 * and KeyScheduler class.
 *
 */
public class AkelarreTest extends TestCase {

	/**
	 * Perform any operations that need to be done prior to each test.
	 */
    @Before
    public void setUp() {}


    /**
     * Perform any operations that need to be done after each test has run.
     */
    @After
    public void tearDown() {}

    /**
     * Tests the 128-bit left rotation function.
     */
    @Test
    public void testInt128RotL(){
        int[] out = {0xFFFFFFFF, 0xFF000000, 0, 0xF};
    	Akelarre.rotl128(out, 32);
    	assertEquals(0xFF000000,out[0]);
    	assertEquals(0,out[1]);
    	assertEquals(0xF,out[2]);
    	assertEquals(0xFFFFFFFF,out[3]);
    }

    /**
     * Tests the 31bit rotation function.
     */
    @Test
    public void testAdditionShift(){
    	//Validate upper rotation
    	int out = Akelarre.rotl31(0x80000001, 1);

    	assertEquals(out, 3 );

    	out = Akelarre.rotl31(0x80000001, 3);
    	assertEquals(out, 9 );

    	out = Akelarre.rotl31(0xA007001, 4);
    	assertEquals(out, 0xA0070001 );

    	//Validate lower rotation
    	out = Akelarre.rotl1(0x1FE70001, 4);

    	assertEquals(out, 0xFE700013 );

     	out = Akelarre.rotl1(0x7E700013, 12);
     	System.out.println(Integer.toHexString(out));
    	assertEquals(out, 0x13FCE );
    }


    /**
     * Tests to make sure the key scheduler is creating correct decryption keys.
     */
    @Test
    public void testDecryptionKeys(){
    	int R = 2;
    	KeyScheduler scheduler = new KeyScheduler(R,8);
    	int[] K = scheduler.schedule(new int[]{0,0});
    	int[] D = scheduler.createDecryptionSubkeys(K);

    	assertEquals(-K[13*R+5],D[0]);
    	assertEquals( K[13*R+6],D[1]);
    	assertEquals( K[13*R+7],D[2]);
    	assertEquals(-K[13*R+8],D[3]);

    	for( int r=0;r<R;r++ ){
    		assertEquals(KeyScheduler.neg(K[13*(R-r)+4]),D[13*r+4]);

    		for( int j=5;j<=16;j++ ){
    			assertEquals(K[13*(R-r-1)+5],D[13*r+5]);
    		}
    	}

    	assertEquals(KeyScheduler.neg(K[4]),D[13*R+4]);
    	assertEquals(-K[0],D[13*R+5]);
    	assertEquals( K[1],D[13*R+6]);
    	assertEquals( K[2],D[13*R+7]);
    	assertEquals(-K[3],D[13*R+8]);
    }

    /**
     * Tests the negation function used in the key scheduler.
     */
    @Test
    public void testNeg(){
    	int test    = 0xA5B5C5D5;
    	int correct = 0xA5B5C5AB;

    	assertEquals(correct,KeyScheduler.neg(test));
    }


    /**
     * Tests the entire Akelarre application by encryption some text and then
     * decrypting the same text to make sure it is correct.
     */
    @Test
    public void testEncryptDecrypt(){
    	for( int r=1;r<=10;r++ ){
	    	Akelarre k = new Akelarre(r,8,new int[]{0xADECF231,0xDBC87943});
	    	int[] plaintext = {1111,2222,3333,4444};
	    	int[] out = k.decrypt( k.encrypt( plaintext ) );
	    	for( int i=0;i<out.length;i++ ){
	    		assertEquals(plaintext[i],out[i]);
	    	}
    	}
    }


}
