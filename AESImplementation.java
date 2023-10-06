import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.ResourceBundle;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.imageio.ImageIO;

import application.constants.SecurityConstants;
import application.utils.AESUtils;
class Encryption{
  private String newFileName;
public  void encryptFileByAES(String algorithm, SecretKey key, byte[] iv,
		    File inputFile) throws IOException, NoSuchPaddingException,
		    NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
		    BadPaddingException, IllegalBlockSizeException {
			newFileName = SecurityConstants.LOCATION + File.separator + newFileName;
			File outputFile = new File(newFileName);
		    Cipher cipher = Cipher.getInstance(algorithm);
		    cipher.init(Cipher.ENCRYPT_MODE, key,  new IvParameterSpec(iv));
		    FileInputStream inputStream = new FileInputStream(inputFile);
		    FileOutputStream outputStream = new FileOutputStream(outputFile);
		    outputStream.write(iv);
		    byte[] buffer = new byte[64];
		    int bytesRead;
		    while ((bytesRead = inputStream.read(buffer)) != -1) {
		        byte[] output = cipher.update(buffer, 0, bytesRead);
		        if (output != null) {
		            outputStream.write(output);
		        }
		    }
		    byte[] outputBytes = cipher.doFinal();
		    
		    if (outputBytes != null) {
		        outputStream.write(outputBytes);
		    }
		    inputStream.close();
		    outputStream.close();
		    byte[] fileContent = Files.readAllBytes(Paths.get(outputFile.getAbsolutePath())); 
		    System.out.println("From encryption -- length of outputBytes " + fileContent.length);
		  
		    outputFile.setReadOnly();
		    outputFile.setWritable(false);
		 
	}
	public File decryptFileByAES(String algorithm, File cipherFile, SecretKey key,
		    byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
		    InvalidAlgorithmParameterException, InvalidKeyException,
		    BadPaddingException, IllegalBlockSizeException, IOException {
		String fileName = cipherFile.getName();
		String type = fileName.substring( fileName.lastIndexOf('.') + 1);
		fileName = fileName.substring(0, fileName.lastIndexOf('.'));
		fileName = fileName + "_decrypted."+ type;
		String filePath =  SecurityConstants.LOCATION+ File.separator + fileName;
		File outputFile = new File(filePath);
		
		    Cipher cipher = Cipher.getInstance(algorithm);
		  
		    FileInputStream inputStream = new FileInputStream(cipherFile);
		    FileOutputStream outputStream = new FileOutputStream(outputFile);
		 
		    byte[] fileContent = Files.readAllBytes(Paths.get(cipherFile.getAbsolutePath())); 
		    byte[] iv1 = new byte[16];
		    byte[] fileEncryptedContent = new byte[fileContent.length - 16];
		    for(int i = 0 ; i < 16 ; i++)
		    {
		    	iv1[i] = fileContent[i];
		    }
		    for(i=16;i<fileContent.length;i++)
		    {
		        fileEncryptedContent[i-16]=fileContent[i];
		      
		    }
		    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv1));
		    
		    System.out.println(fileContent.toString());
		    System.out.println("Length of encypted file content - "+fileEncryptedContent.length);
		    System.out.println(fileContent.length);
		    
		    byte[] plainText = cipher.doFinal(fileEncryptedContent);
		    System.out.println(plainText.toString());
		    if (plainText != null && type.equalsIgnoreCase("txt")) {
		        outputStream.write(plainText);
		    }
		 
		    ByteArrayInputStream bis = new ByteArrayInputStream(plainText);
		    BufferedImage bImage2 = ImageIO.read(bis);
		    ImageIO.write(bImage2, "jpg", new File(fileName));
		    Files.write(Paths.get(filePath), plainText);
		    
		    return outputFile;
		}
}
