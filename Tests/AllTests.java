package Tests;

import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * The purpose of this class was to run all test cases that we created during the course
 * of our project. In the end we only ended up creating tests for the encryption
 * and decryption part of our algorithm.
 *
 */
public class AllTests {

	public static Test suite() {
		TestSuite suite = new TestSuite("Test for Tests");
		//$JUnit-BEGIN$
		suite.addTestSuite(AkelarreTest.class);
		//$JUnit-END$
		return suite;
	}

}
