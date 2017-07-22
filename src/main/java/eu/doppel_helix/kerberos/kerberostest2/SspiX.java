package eu.doppel_helix.kerberos.kerberostest2;



import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import static com.sun.jna.Structure.createFieldsOrder;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.win32.W32APITypeMapper;
import java.util.List;

public interface SspiX extends Sspi {

    public static final int SECPKG_CRED_ATTR_NAMES = 1;
    public static final int SECPKG_CRED_ATTR_SSI_PROVIDER = 2;
    public static final int SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS = 3;
    public static final int SECPKG_CRED_ATTR_CERT = 4;
    public static final int SECPKG_ATTR_SESSION_KEY = 9;
    public static final int SECPKG_ATTR_KEY_INFO = 5;
    public static final int SECPKG_ATTR_LIFESPAN = 2;
    public static final int SECPKG_ATTR_SIZES = 0;
    public static final int SECPKG_ATTR_NEGOTIATION_INFO = 12;
    public static final int SECPKG_ATTR_FLAGS = 14;
    public static final int SECPKG_ATTR_STREAM_SIZES = 4;
    public static final int SECBUFFER_STREAM_TRAILER = 6;
    public static final int SECBUFFER_STREAM_HEADER = 7;
    public static final int SECBUFFER_PADDING = 9;
    public static final int SECBUFFER_STREAM = 10;
    
    
    /**
     * Produce a header or trailer but do not encrypt the message.
     */
    public static final int SECQOP_WRAP_NO_ENCRYPT = 0x80000001;

    public static class SecPkgCredentials_Names extends Structure {

        public static class ByReference extends SecPkgCredentials_Names implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("sUserName");

        /**
         * The first entry in an array of SecPkgInfo structures.
         */
        public Pointer sUserName;

        public SecPkgCredentials_Names() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        public synchronized String getUserName() {
            if(sUserName == null) {
                return null;
            }
            return Boolean.getBoolean("w32.ascii") ? sUserName.getString(0) : sUserName.getWideString(0);
        }
        
        public synchronized void free() {
            if(sUserName != null) {
                Secur32X.INSTANCE.FreeContextBuffer(sUserName);
                sUserName = null;
            }
        }
    }
    
    public static class SecPkgContext_SessionKey extends Structure {

        public static class ByReference extends SecPkgContext_SessionKey implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("SessionKeyLength", "SessionKey");

        /**
         * Size, in bytes, of the session key.
         */
        public NativeLong SessionKeyLength;
        
        /**
         * The session key for the security context.
         */
        public Pointer SessionKey;

        public SecPkgContext_SessionKey() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        public byte[] getSessionKey() {
            if(SessionKey == null) {
                return null;
            }
            return SessionKey.getByteArray(0, SessionKeyLength.intValue());
        }
        
        public synchronized void free() {
            if(SessionKey != null) {
                Secur32X.INSTANCE.FreeContextBuffer(SessionKey);
                SessionKey = null;
            }
        }
    }
    
    public static class SecPkgContext_KeyInfo extends Structure {

        public static class ByReference extends SecPkgContext_KeyInfo implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("sSignatureAlgorithmName", "sEncryptAlgorithmName","KeySize", "SignatureAlgorithm", "EncryptAlgorithm");

        /**
         * Name, if available, of the algorithm used for generating signatures, for example "MD5" or "SHA-2".
         */
        public Pointer sSignatureAlgorithmName;
        
        /**
         * Name, if available, of the algorithm used for encrypting messages. Reserved for future use.
         */
        public Pointer sEncryptAlgorithmName;
        
        /**
         * Specifies the effective key length, in bits, for the session key. This is typically 40, 56, or 128 bits.
         */
        public int KeySize;
        
        /**
         * Specifies the algorithm identifier (ALG_ID) used for generating signatures, if available.
         */
        public int SignatureAlgorithm;
        
        /**
         * Specifies the algorithm identifier (ALG_ID) used for encrypting messages. Reserved for future use.
         */
        public int EncryptAlgorithm;

        public SecPkgContext_KeyInfo() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        public synchronized String getSignatureAlgorithmName() {
            if(sSignatureAlgorithmName == null) {
                return null;
            }
            return Boolean.getBoolean("w32.ascii") ? sSignatureAlgorithmName.getString(0) : sSignatureAlgorithmName.getWideString(0);
        }
        
        public synchronized String getEncryptAlgorithmName() {
            if(sEncryptAlgorithmName == null) {
                return null;
            }
            return Boolean.getBoolean("w32.ascii") ? sEncryptAlgorithmName.getString(0) : sEncryptAlgorithmName.getWideString(0);
        }
        
        public synchronized void free() {
            if(sSignatureAlgorithmName != null) {
                Secur32X.INSTANCE.FreeContextBuffer(sSignatureAlgorithmName);
                sSignatureAlgorithmName = null;
            }
            if(sEncryptAlgorithmName != null) {
                Secur32X.INSTANCE.FreeContextBuffer(sEncryptAlgorithmName);
                sEncryptAlgorithmName = null;
            }
        }
    }
    
    public static class SecPkgContext_Lifespan extends Structure {

        public static class ByReference extends SecPkgContext_Lifespan implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("tsStart", "tsExpiry");

        /**
         * Time at which the context was established.
         */
        public int tsStart;
        
        /**
         * Time at which the context will expire.
         */
        public Pointer tsExpiry;

        public SecPkgContext_Lifespan() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
    }
    
    public static class SecPkgContext_Sizes extends Structure {

        public static class ByReference extends SecPkgContext_Sizes implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("cbMaxToken", "cbMaxSignature", "cbBlockSize", "cbSecurityTrailer");

        /**
         * Specifies the maximum size of the security token used in the authentication exchanges.
         */
        public int cbMaxToken;
        
        /**
         * Specifies the maximum size of the signature created by the MakeSignature function. This member must be zero if integrity services are not requested or available.
         */
        public int cbMaxSignature;
        
        /**
         * Specifies the preferred integral size of the messages. For example, eight indicates that messages should be of size zero mod eight for optimal performance. Messages other than this block size can be padded.
         */
        public int cbBlockSize;
        
        /**
         * Size of the security trailer to be appended to messages. This member should be zero if the relevant services are not requested or available.
         */
        public int cbSecurityTrailer;

        public SecPkgContext_Sizes() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        @Override
        public String toString() {
            return "SecPkgContext_Sizes{" + "cbMaxToken=" + cbMaxToken +
                    ", cbMaxSignature=" + cbMaxSignature + ", cbBlockSize=" +
                    cbBlockSize + ", cbSecurityTrailer=" + cbSecurityTrailer +
                    '}';
        }
        
        
    }
    
    public static class SecPkgContext_NegotiationInfo extends Structure {

        public static class ByReference extends SecPkgContext_NegotiationInfo implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("PackageInfo", "NegotiationState");

        /**
         * Time at which the context was established.
         */
        public PSecPkgInfo PackageInfo;

        /**
         * Time at which the context will expire.
         */
        public NativeLong NegotiationState;

        public SecPkgContext_NegotiationInfo() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
        
        public void free() {
            if(PackageInfo != null) {
                Secur32X.INSTANCE.FreeContextBuffer(PackageInfo.getPointer());
                PackageInfo = null;
            }
        }
    }
    
    public static class SecPkgContext_StreamSizes extends Structure {

        public static class ByReference extends SecPkgContext_StreamSizes implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("cbHeader", "cbTrailer", "cbMaximumMessage", "cBuffers", "cbBlockSize");

        /**
         * Specifies the size, in bytes, of the header portion. If zero, no header is used.
         */
        public int cbHeader;
        
        /**
         * Specifies the maximum size, in bytes, of the trailer portion. If zero, no trailer is used.
         */
        public int cbTrailer;
        
        /**
         * Specifies the size, in bytes, of the largest message that can be encapsulated.
         */
        public int cbMaximumMessage;
        
        /**
         * Specifies the number of buffers to pass.
         */
        public int cBuffers;
        
        /**
         * Specifies the preferred integral size of the messages. For example, eight indicates that messages should be of size zero mod eight for optimal performance. Messages other than this block size can be padded.
         */
        public int cbBlockSize;

        public SecPkgContext_StreamSizes() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        @Override
        public String toString() {
            return "SecPkgContext_StreamSizes{" + "cbHeader=" + cbHeader +
                    ", cbTrailer=" + cbTrailer + ", cbMaximumMessage=" +
                    cbMaximumMessage + ", cBuffers=" + cBuffers +
                    ", cbBlockSize=" + cbBlockSize + '}';
        }
        
    }
    
    public static class SecPkgContext_Flags extends Structure {

        public static class ByReference extends SecPkgContext_Flags implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("Flags");

        /**
         * Flag values for the current security context. These values correspond to the flags negotiated by the InitializeSecurityContext (General) and AcceptSecurityContext (General) functions.
         */
        public int Flags;

        public SecPkgContext_Flags() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
    }
}