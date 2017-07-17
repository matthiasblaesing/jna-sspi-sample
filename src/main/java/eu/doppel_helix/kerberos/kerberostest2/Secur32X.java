package eu.doppel_helix.kerberos.kerberostest2;




import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.W32APIOptions;

public interface Secur32X extends Secur32 {

    public static Secur32X INSTANCE = Native.loadLibrary("Secur32", Secur32X.class, W32APIOptions.DEFAULT_OPTIONS);

    /**
     * Retrieves the attributes of a credential, such as the name associated
     * with the credential. The information is valid for any security context
     * created with the specified credential.
     *
     * @param phContext   A handle of the credentials to be queried.
     * @param ulAttribute Specifies the attribute of the context to be returned.
     *                    This parameter can be one of the SECPKG_ATTR_* values
     *                    defined in {@link Sspi}.
     * @param pBuffer     A pointer to a structure that receives the attributes.
     *                    The type of structure pointed to depends on the value
     *                    specified in the ulAttribute parameter.
     * @return If the function succeeds, the return value is SEC_E_OK. If the
     *         function fails, the return value is a nonzero error code.
     */
    int QueryCredentialsAttributes(Sspi.CredHandle phCredential, int ulAttribute, Structure pBuffer);
    
    /**
     * Retrieves information about a specified security package. This
     * information includes the bounds on sizes of authentication information,
     * credentials, and contexts.
     *
     * @param pszPackageName Name of the security package.
     * @param ppPackageInfo  Variable that receives a pointer to a SecPkgInfo
     *                       structure containing information about the
     *                       specified security package.
     * @return  If the function succeeds, the return value is SEC_E_OK.
     * If the function fails, the return value is a nonzero error code.
     */
    int QuerySecurityPackageInfo(String pszPackageName, Sspi.PSecPkgInfo ppPackageInfo);
    
    /**
     * EncryptMessage (Kerberos) function
     * 
     * <p>
     * The EncryptMessage (Kerberos) function encrypts a message to provide
     * privacy. EncryptMessage (Kerberos) allows an application to choose among
     * cryptographic algorithms supported by the chosen mechanism. The
     * EncryptMessage (Kerberos) function uses the security context referenced
     * by the context handle. Some packages do not have messages to be encrypted
     * or decrypted but rather provide an integrity hash that can be
     * checked.</p>
     *
     * @param phContext A handle to the security context to be used to encrypt
     *                  the message.
     * @param fQOP      Package-specific flags that indicate the quality of
     *                  protection. A security package can use this parameter to
     *                  enable the selection of cryptographic algorithms. This
     *                  parameter can be the following flag:
     *                  {@link SspiX.SECQOP_WRAP_NO_ENCRYPT}.
     * @param pMessage  A pointer to a SecBufferDesc structure. On input, the
     *                  structure references one or more SecBuffer structures
     *                  that can be of type SECBUFFER_DATA. That buffer contains
     *                  the message to be encrypted. The message is encrypted in
     *                  place, overwriting the original contents of the
     *                  structure.
     *
     * <p>
     * The function does not process buffers with the SECBUFFER_READONLY
     * attribute.</p>
     *
     * <p>
     * The length of the SecBuffer structure that contains the message must be
     * no greater than cbMaximumMessage, which is obtained from the
     * QueryContextAttributes (Kerberos) (SECPKG_ATTR_STREAM_SIZES)
     * function.</p>
     *
     * <p>
     * Applications that do not use SSL must supply a SecBuffer of type
     * SECBUFFER_PADDING.</p>
     * @param MessageSeqNo The sequence number that the transport application
     *                     assigned to the message. If the transport application
     *                     does not maintain sequence numbers, this parameter
     *                     must be zero.
     * @return If the function succeeds, the function returns SEC_E_OK.
     * @see <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa375385(v=vs.85).aspx">MSDN Entry</a>
     */
    int EncryptMessage(CtxtHandle phContext, int fQOP, Sspi.SecBufferDesc pMessage, int MessageSeqNo);
    
    /**
     * DecryptMessage (Kerberos) function
     *
     * <p>
     * The DecryptMessage (Kerberos) function decrypts a message. Some packages
     * do not encrypt and decrypt messages but rather perform and check an
     * integrity hash.</p>
     *
     * @param phContext    A handle to the security context to be used to
     *                     encrypt the message.
     * @param pMessage     A pointer to a SecBufferDesc structure. On input, the
     *                     structure references one or more SecBuffer structures
     *                     that may be of type SECBUFFER_DATA. The buffer
     *                     contains the encrypted message. The encrypted message
     *                     is decrypted in place, overwriting the original
     *                     contents of its buffer.
     * @param MessageSeqNo The sequence number expected by the transport
     *                     application, if any. If the transport application
     *                     does not maintain sequence numbers, this parameter
     *                     must be set to zero.
     * @param pfQOP        A pointer to a variable of type ULONG that receives
     *                     package-specific flags that indicate the quality of
     *                     protection. This parameter can be the following flag:
     *                     {@link SspiX.SECQOP_WRAP_NO_ENCRYPT}.
     * @return If the function verifies that the message was received in the correct sequence, the function returns SEC_E_OK.
     * @see <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa375385(v=vs.85).aspx">MSDN Entry</a>
     */
    int DecryptMessage(CtxtHandle phContext, Sspi.SecBufferDesc pMessage, int MessageSeqNo, IntByReference pfQOP);
}
