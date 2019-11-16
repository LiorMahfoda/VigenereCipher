///********************************************////
/*	Author: Lior Mahfoda
    ID: 302782230
	Assignment number 1
	Course : Security Software, SCE
*/
////******************************************///

package ciper;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class  VigenereCipher {
	
	///Task #1

	/**
	 * Encryption function of Vigenere cipher
	 * 
	 * @param text 
	 * 			2 strings plaintext & key
	 * @return Encrypyion of the cipher
	 */
	static String encrypt(String text, final String key) {
		if (!key.matches("[a-zA-Z]+"))
	        throw new IllegalArgumentException("Invalid key - must be one or more characters in range a...z");
		String res = "";
	    text = text.toUpperCase();
	    for (int i = 0, j = 0; i < text.length(); i++) {
	    	char c = text.charAt(i);
	        	if (c < 'A' || c > 'Z')
	        		continue;
	            res += (char)((c + key.charAt(j) - 2 * 'A') % 26 + 'A');
	            j = ++j % key.length();
	        }
	    return res;
	}
	
	/**
	 * Decryption function of Vigenere cipher
	 * 
	 * @param text
	 * 		2 strings plaintext & key
	 * @return Decryption of the cipher
	 */
	public static String decrypt(String text, final String key) {
		if (key == null || !key.matches("[a-zA-Z]+"))
	        throw new IllegalArgumentException("Invalid key - must be one or more characters in range a...z");
		String res = "";
	    text = text.toUpperCase();
	    for (int i = 0, j = 0; i < text.length(); i++) {
	    	char c = text.charAt(i);
	        	if (c < 'A' || c > 'Z') 
	        		continue;
	         	res += (char)((c - key.charAt(j) + 26) % 26 + 'A');
	            j = ++j % key.length();
	    }
	    return res;
	}
	
	///End of task #1 

	///Task #2
	/**
	 * Function returns True/False whether a letter is UpperCase or not
	 * 
	 * @param char
	 *            a single Character
	 * @return True/False statement
	 */
	public static boolean isUpperCase(char ch) {
	    return ch >= 'A' && ch <= 'Z';
	}
	
	/**
	 * Function that count how much time appears every upper letter A-Z
	 * 
	 * @param text
	 *            a string encrypted with a Vigenere cipher
	 * @return array of intgers from 0-25 to represent A-Z UpperCase
	 */
	public static int[] Appearances(String text,boolean callback){
		int size = text.length();
		int index;
		final char[] Letters = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','O','R','S','T','U','V','W','X','Y','Z'};
		int[] Appears = new int[Letters.length]; // array to count A-Z letters
		
		/// Initialize the array of letters appearances to 0
		for (int i=0;i<Letters.length;i++){
			Appears[i] = 0;
		}
		for (int i=0;i<Letters.length;i++){
			index = Character.getNumericValue(Letters[i])-10; // Casting current letter to integer
			for(int j=0;j<size;j++){
				if(isUpperCase(text.charAt(j))&& text.charAt(j)==Letters[i])  // Range  of upper letters
				    	Appears[index]+=1;   // Increase by 1
			} // 2'nd for
		 // 1'st for
		}
		if(callback){
			System.out.println("\nFrequency of each letter in the ciphertext:\n");
			for(int i=0;i<26;i++)
				System.out.println("The Letter:" +Letters[i]+ " And its frequacy is: " + Appears[i]);
			System.out.println("");
		}
		return Appears;
	}
	///End of task #2
	
	/**
	 * Calculates the Index of Coincidence based on the supplied letter
	 * frequency array
	 * 
	 * @param frequencies
	 *            an array containing the letter frequencies of a text
	 *  {@value C = 26(values.length - A"B letters)
	 *  		N- text length}
	 *            
	 * @return the Index of Coincidence
	 * */
	@SuppressWarnings("null")
	public static int calculateIC(String text, int[] values){
        float[] arrayAvgIC = new float[15];// array for each guess K( key) for each AVG ICs
        String substring;
        int plainLen = text.length();
        float IC;
        float avgICs;

        //for every guess of the key K: 2-15
        for (int k = 2; k <= 15; k++){
            float sumICs = 0;
            for (int i = 0; i < k; i++){
                substring = "";//a sub string of the cipher text for every column
                //building the sub string
                for (int j = 0; j < plainLen; j++){
                    //for example if the index of a letter mod k=3 is i=0
                    if (j % k == i)
                    	substring += text;
                }//end for tstro build strComp
                int strComp = substring.length();

                //now we compute the IC based on the formula
                IC = 0;
                for (int j = 0; j < 26; j++)
                    IC += values[j] * (values[j] - 1);

                IC = IC / (strComp * (strComp - 1));
                sumICs += IC * 26;

            }
            //we now do AVG of all of the ICs based on guess K( key) and we put the result on the arrayAvgIC
            avgICs = sumICs / k;
            arrayAvgIC[k - 1] = avgICs;
        }

        //now we find the max of all of the AVGs of ICs of key: 2-15 to see what is the length of the key
        int index = 0;
        for (int i = 0; i < arrayAvgIC.length; i++)
            if (arrayAvgIC[i] >= arrayAvgIC[index])
                index = i;

        //and we return the key's length
        return index;
    }
	
	public static double maxIc(double[] ic){
		double max = ic[0];
		for (int i=1;i<ic.length;i++)
			if (ic[i]>max)
				max = ic[i];
		System.out.println("MaxIc = " + max);
		return max;
	} 
	
	/**
	 * Estimates the keylength of a give string encrypted with a Vigenere cipher
	 * 
	 * @param text
	 *            a string encrypted with a Vigenere cipher
	 * @return the approximate key length of the key used to encrypt the text
	 */
	public static int estimateKeyLength(String text) { 
		double ic = calculateIC(text, Appearances(text,false));
		return (int)ic;
	}
	//End of task #3
	
	/**
	 *  Function gives the keywork of the cipher
	 * 
	 * @param text
	 *            a string representing ciphertext
	 * @return string to represent the key
	 */
	
    public static String keyword(String text,int keyLen){
        String strCmp;
        String helpStr = "";
        String key = "";
        double[] X = new double[26];
        double sum;
        int indexMax;
        int[] countLetters = null;
        double[] prevalence = null;
        double[] frequency = {0.082, 0.015, 0.028,  // array represents table of relative prevalence
			    			0.043, 0.127, 0.022,
			    			0.020, 0.061, 0.070, 
			    			0.002, 0.008, 0.040,
			    			0.024, 0.067, 0.075,
			    			0.019, 0.001, 0.060, 
			    			0.063, 0.091, 0.028, 
			    			0.010, 0.023, 0.001, 
			    			0.020, 0.001};
       
        for (int i = 0; i < keyLen; i++){
            strCmp = "";
            for (int j = 0; j < text.length(); j++)
                if (j % keyLen == i)     
                  strCmp += text.charAt(j);
            
            System.out.println(strCmp);
            for (int j = 0; j < 26; j++){
                helpStr = decrypt(strCmp, Character.toString((char) j));
                countLetters = Appearances(helpStr,false);
                prevalence = new double[countLetters.length];
                
                for (int z = 0; z < countLetters.length; z++)
                	prevalence[z] = (double)countLetters[z] / helpStr.length();
                
                sum = 0;
                for (int z = 0; z < prevalence.length; z++)
                    sum = sum + prevalence[z] * (frequency[z]);
                X[j] = sum;
            
            indexMax = (int) maxIc(X);
            key = key + String.valueOf(indexMax + 'A');
            }
        }
        return key;
    }
  ///*** End of #4 ***///
	
    //Task 5
    public static String decryptWithoutKey(String text){  	
        int keyLen;
        String key,res;
        if (text == null || !text.matches("[a-zA-Z]+"))
	        throw new IllegalArgumentException("Invalid key - must be one or more characters in range a...z");
        keyLen = estimateKeyLength(text);
        key = keyword(text,keyLen);//now that we have the key's length we find the actual key
        res = decrypt(text, key);//now that we have the actual key,we use the decrypt method from Form1 with the key and the cipher text
		return res;
    	
    }
    
	public static void main(String[] args) throws FileNotFoundException{
		boolean callback = true; // Flag to indicate if to display list of Appearances or not
		// File path
		final String Filename = "C:\\Users\\LIOR\\workspace\\ciper\\src\\ciper\\plaintext.txt"; 
		try {
			List<String> lines = Files.readAllLines(Paths.get(Filename));
			String str = String.join("", lines); // convert List to string
			String key = "FORTIFYFORTIFYFORTIFY"; // key example
			String encr = encrypt(str, key);
			System.out.println("Original Message: " + str);
			System.out.println("\nKey: " + key);
			System.out.println("\nEncrypted Message: " + encr); // Activate #1
			System.out.println("\nDecrypted Message: " + decrypt(encr,key)); // Activate #1
			Appearances(encr,callback); // Activate #2
			System.out.println();
			int keyLen = estimateKeyLength(encr); 
			System.out.println("\nEstimated key length: "+ keyLen); // Activate #3
			System.out.println("Keyword is: "+ keyword(encr,keyLen));// Activate #4
			System.out.println("The decryption is: "+ decryptWithoutKey(encr)); // Activate #5
			} 
		catch (IOException e) {
			e.printStackTrace();
		} // End of try-catch
		
	} // End of Main
} // end of Class

