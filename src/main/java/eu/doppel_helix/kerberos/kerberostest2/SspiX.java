package eu.doppel_helix.kerberos.kerberostest2;



import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import static com.sun.jna.Structure.createFieldsOrder;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.win32.W32APITypeMapper;
import java.util.Date;
import java.util.List;

public interface SspiX extends Sspi {

    public static final int SECPKG_CRED_ATTR_NAMES = 1;
    
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
    public static final int ISC_REQ_DATAGRAM = 0x00000400;

    /**
     * Negotiation has been completed.
     */
    int SECPKG_NEGOTIATION_COMPLETE = 0;
    /**
     * Negotiations not yet completed.
     */
    int SECPKG_NEGOTIATION_OPTIMISTIC = 1;
    /**
     * Negotiations in progress.
     */
    int SECPKG_NEGOTIATION_IN_PROGRESS = 2;
    int SECPKG_NEGOTIATION_DIRECT = 3;
    int SECPKG_NEGOTIATION_TRY_MULTICRED = 4;
    
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
        public int SessionKeyLength;
        
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
            return SessionKey.getByteArray(0, SessionKeyLength);
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
        public TimeStamp tsStart;
        
        /**
         * Time at which the context will expire.
         */
        public TimeStamp tsExpiry;

        public SecPkgContext_Lifespan() {
            super(W32APITypeMapper.DEFAULT);
        }

        public Date getStartAsDate()  {
            if(tsStart != null && (tsStart.dwLower != 0 || tsStart.dwUpper != 0)) {
                return WinBase.FILETIME.filetimeToDate(tsStart.dwUpper, tsStart.dwLower);
            }
            return null;
        }
        
        public Date getExpiryAsDate()  {
            if(tsExpiry != null && (tsExpiry.dwLower != 0 || tsExpiry.dwUpper != 0)) {
                return WinBase.FILETIME.filetimeToDate(tsExpiry.dwUpper, tsExpiry.dwLower);
            }
            return null;
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
        public int NegotiationState;

        public SecPkgContext_NegotiationInfo() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
        
        public synchronized void free() {
            if(PackageInfo != null) {
                Secur32X.INSTANCE.FreeContextBuffer(PackageInfo.pPkgInfo.getPointer());
                PackageInfo = null;
            }
        }
    }
    
    public static class SecPkgContext_Flags extends Structure {

        public static class ByReference extends SecPkgContext_Flags implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("Flags");

        /**
         * Flag values for the current security context. These values correspond
         * to the flags negotiated by the InitializeSecurityContext (General)
         * and AcceptSecurityContext (General) functions.
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
    
    public static class ManagedSecBufferDesc extends SecBufferDesc2 {
                
        private final SecBuffer[] secBuffers;
        
        /**
         * Create a new SecBufferDesc with initial data.
         * @param type Token type.
         * @param token Initial token data.
         */
        public ManagedSecBufferDesc(int type, byte[] token) {
            secBuffers = new SecBuffer[] { new SecBuffer(type, token) };
            pBuffers = secBuffers[0].getPointer();
            cBuffers = secBuffers.length;
        }

        /**
         * Create a new SecBufferDesc with one SecBuffer of a given type and size.
         * @param type type
         * @param tokenSize token size
         */
        public ManagedSecBufferDesc(int type, int tokenSize) {
            secBuffers = new SecBuffer[] { new SecBuffer(type, tokenSize) };
            pBuffers = secBuffers[0].getPointer();
            cBuffers = secBuffers.length;
        }
        
        public ManagedSecBufferDesc(int bufferCount) {
            cBuffers = bufferCount;
            secBuffers = (SecBuffer[]) new SecBuffer().toArray(2);
            pBuffers = secBuffers[0].getPointer();
            cBuffers = secBuffers.length;
        }

        public SecBuffer getBuffer(int idx) {
            return secBuffers[idx];
        }

        @Override
        public void write() {
            for(SecBuffer sb: secBuffers)  {
                sb.write();
            }
            writeField("ulVersion");
            writeField("pBuffers");
            writeField("cBuffers");
        }

        @Override
        public void read() {
            for (SecBuffer sb : secBuffers) {
                sb.read();
            }
        }

    }
    
    public static class SecBufferDesc2 extends Structure {
        public static final List<String> FIELDS = createFieldsOrder("ulVersion", "cBuffers", "pBuffers");

        /**
         * Version number.
         */
        public int ulVersion = SECBUFFER_VERSION;
        /**
         * Number of buffers.
         */
        public int cBuffers = 1;
        /**
         * Pointer to array of buffers.
         */
        public Pointer pBuffers;

        /**
         * Create a new SecBufferDesc with one SECBUFFER_EMPTY buffer.
         */
        public SecBufferDesc2() {
            super();
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
    }
    
    public static final int SEC_WINNT_AUTH_IDENTITY_ANSI = 0x1;
    public static final int SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2;

    
    public static class SEC_WINNT_AUTH_IDENTITY extends Structure {

        public static final List<String> FIELDS = createFieldsOrder("User", "UserLength", "Domain", "DomainLength", "Password", "PasswordLength", "Flags");

        /**
         * A string that contains the user name.
         */
        public String User;

        /**
         * The length, in characters, of the user string, not including the
         * terminating null character.
         */
        public int UserLength;

        /**
         * A string that contains the domain name or the workgroup name.
         */
        public String Domain;

        /**
         * The length, in characters, of the domain string, not including the
         * terminating null character.
         */
        public int DomainLength;

        /**
         * A string that contains the password of the user in the domain or
         * workgroup. When you have finished using the password, remove the
         * sensitive information from memory by calling SecureZeroMemory. For
         * more information about protecting the password, see Handling
         * Passwords.
         */
        public String Password;

        /**
         * The length, in characters, of the password string, not including the
         * terminating null character.
         */
        public int PasswordLength;

        /**
         * This member can be one of the following values.
         *
         * <table>
         * <tr><th>Value</th><th>Meaning</th></tr>
         * <tr><td>SEC_WINNT_AUTH_IDENTITY_ANSI</td><td>The strings in this structure are in ANSI format.</td></tr>
         * <tr><td>SEC_WINNT_AUTH_IDENTITY_UNICODE</td><td>The strings in this structure are in Unicode format.</td></tr>
         * </table>
         *
         * <strong>As the string encoding is managed by JNA do not change this
         * value!</strong>
         */
        public int Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    

        /**
         * Create a new SecBufferDesc with one SECBUFFER_EMPTY buffer.
         */
        public SEC_WINNT_AUTH_IDENTITY() {
            super(W32APITypeMapper.UNICODE);
        }

        @Override
        public void write() {
            UserLength = User == null ? 0 : User.length();
            DomainLength = Domain == null ? 0 : Domain.length();
            PasswordLength = Password == null ? 0 : Password.length();
            super.write();
        }
        
        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
    }
}
