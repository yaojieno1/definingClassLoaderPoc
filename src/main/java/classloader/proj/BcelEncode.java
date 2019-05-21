package classloader.proj;


import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import org.apache.commons.io.IOUtils;
import com.sun.org.apache.bcel.internal.classfile.Utility;

public class BcelEncode {
	
	private static byte[] readClass (String cls) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			IOUtils.copy(new FileInputStream(new File(cls)), bos);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return bos.toByteArray();
	}

	public static String encode (String classFilePath) throws Exception{
        byte[] data = readClass(classFilePath);
        return Utility.encode(data,true);
    }
}