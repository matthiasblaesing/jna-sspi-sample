package eu.doppel_helix.kerberos.kerberostest2;

import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.platform.win32.Sspi.PSecPkgInfo;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.ptr.IntByReference;
import java.nio.charset.Charset;

public class Sample {

    public static void main(String[] args) {
        final String packageName = "Kerberos";
        
        PSecPkgInfo pkgInfo = new PSecPkgInfo();
        ensureOk(Secur32X.INSTANCE.QuerySecurityPackageInfo(packageName, pkgInfo));
        
        final TimeStamp clientTimestamp = new TimeStamp();
        final TimeStamp serverTimestamp = new TimeStamp();
        final CredHandle serverCred = new CredHandle();
        final CredHandle clientCred = new CredHandle();
        
        ensureOk(Secur32X.INSTANCE.AcquireCredentialsHandle(null, packageName, SspiX.SECPKG_CRED_INBOUND, null, null, null, null, serverCred, serverTimestamp));
        ensureOk(Secur32X.INSTANCE.AcquireCredentialsHandle(null, packageName, SspiX.SECPKG_CRED_OUTBOUND, null, null, null, null, clientCred, clientTimestamp));
        
        SspiX.SecPkgCredentials_Names names = new SspiX.SecPkgCredentials_Names();
        ensureOk(Secur32X.INSTANCE.QueryCredentialsAttributes(serverCred, SspiX.SECPKG_CRED_ATTR_NAMES, names));
        
        String serverName = names.getUserName();
        
        names.free();
        
        CtxtHandle clientCtx = new CtxtHandle();
        CtxtHandle serverCtx = new CtxtHandle();
        
        IntByReference serverContextAttr = new IntByReference();
        IntByReference clientContextAttr = new IntByReference();
        
        Sspi.SecBufferDesc serverToken = null;
        int clientRc = W32Errors.SEC_I_CONTINUE_NEEDED;
        int serverRc = W32Errors.SEC_I_CONTINUE_NEEDED;
        do {
            Sspi.SecBufferDesc pbClientToken = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
            if (clientRc == W32Errors.SEC_I_CONTINUE_NEEDED) {
                Sspi.SecBufferDesc pbServerTokenCopy = serverToken == null
                        ? null : new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, serverToken.getBytes());
                clientRc = Secur32.INSTANCE.InitializeSecurityContext(
                        clientCred,
                        clientCtx.isNull() ? null : clientCtx,
                        serverName,
                        Sspi.ISC_REQ_CONFIDENTIALITY | Sspi.ISC_REQ_STREAM,
                        0,
                        Sspi.SECURITY_NATIVE_DREP,
                        pbServerTokenCopy,
                        0,
                        clientCtx,
                        pbClientToken,
                        clientContextAttr,
                        null);
                if(clientRc != W32Errors.SEC_E_OK && clientRc != W32Errors.SEC_I_CONTINUE_NEEDED) {
                    throw new RuntimeException("InitializeSecurityContext failed: " + WinErrorSecMap.resolveString(clientRc));
                }
            }
            if (serverRc == W32Errors.SEC_I_CONTINUE_NEEDED) {
                serverToken = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
                Sspi.SecBufferDesc pbClientTokenByValue = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, pbClientToken.getBytes());
                serverRc = Secur32.INSTANCE.AcceptSecurityContext(
                        serverCred,
                        serverCtx.isNull() ? null : serverCtx,
                        pbClientTokenByValue,
                        Sspi.ISC_REQ_STREAM,
                        Sspi.SECURITY_NATIVE_DREP,
                        serverCtx,
                        serverToken,
                        serverContextAttr,
                        null);
                
                if(serverRc != W32Errors.SEC_E_OK && serverRc != W32Errors.SEC_I_CONTINUE_NEEDED) {
                    throw new RuntimeException("AcceptSecurityContext failed: " + WinErrorSecMap.resolveString(serverRc));
                }
            }
        } while (serverRc != W32Errors.SEC_E_OK || clientRc != W32Errors.SEC_E_OK);

        
        SspiX.SecPkgContext_Sizes sizes = new SspiX.SecPkgContext_Sizes();
        ensureOk(Secur32X.INSTANCE.QueryContextAttributes(clientCtx, SspiX.SECPKG_ATTR_SIZES, sizes));
        
        System.out.println(sizes);
        
        byte[] inputData = "Hallo Welt".getBytes(Charset.forName("ASCII"));
        System.out.println("============ INPUT =============");
        printHexDump(inputData, inputData.length);
        System.out.println("============ CRYPT =============");
        
        Sspi.SecBuffer.ByReference tokenBuffer = new SspiX.SecBuffer.ByReference(SspiX.SECBUFFER_TOKEN, sizes.cbSecurityTrailer);
        Sspi.SecBuffer.ByReference messageBuffer = new SspiX.SecBuffer.ByReference(SspiX.SECBUFFER_DATA, inputData);
        Sspi.SecBuffer.ByReference paddingBuffer = new SspiX.SecBuffer.ByReference(SspiX.SECBUFFER_PADDING, sizes.cbBlockSize);
        Sspi.SecBuffer.ByReference emptyBuffer = new SspiX.SecBuffer.ByReference();
        emptyBuffer.BufferType = SspiX.SECBUFFER_EMPTY;

        Sspi.SecBufferDesc pMessage = new Sspi.SecBufferDesc();
        pMessage.pBuffers = new SspiX.SecBuffer.ByReference[]{tokenBuffer, messageBuffer, paddingBuffer, emptyBuffer};
        pMessage.cBuffers = pMessage.pBuffers.length;

        ensureOk(Secur32X.INSTANCE.EncryptMessage(clientCtx, 0, pMessage, 0));
        
        byte[] header = tokenBuffer.getBytes();
        byte[] messageResult = messageBuffer.getBytes();
        byte[] trailer = paddingBuffer.getBytes();
        printHexDump(header, header.length);
        printHexDump(messageResult, messageResult.length);
        printHexDump(trailer, trailer.length);
    }

    
    private static void ensureOk(int result) {
        if(result != WinError.SEC_E_OK) {
            throw new IllegalStateException(String.format("Call failed (%d): %s", result, WinErrorSecMap.resolveString(result)));
        }
    }
    
    private static final String[] hexDigits = new String[]{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

    private static void printHexDump(byte[] data, int length) {
        StringBuilder rowBuffer = new StringBuilder(100);
        for (int rowOffset = 0; rowOffset < length; rowOffset += 16) {
            rowBuffer.append(String.format("%04x | ", rowOffset));
            for (int i = 0; i < 16; i++) {
                if ((rowOffset + i) < data.length) {
                    byte dataElement = data[rowOffset + i];
                    rowBuffer.append(hexDigits[(dataElement >> 4) & 0x0F]);
                    rowBuffer.append(hexDigits[dataElement & 0x0F]);
                } else {
                    rowBuffer.append("  ");
                }
                if (i == 7) {
                    rowBuffer.append(":");
                } else {
                    rowBuffer.append(" ");
                }
            }
            rowBuffer.append(" | ");
            for (int i = 0; i < 16; i++) {
                if ((rowOffset + i) < data.length) {
                    char c = (char) data[rowOffset + i];
                    if (Character.isWhitespace(c) || c == 0) {
                        rowBuffer.append(" ");
                    } else {
                        rowBuffer.append(c);
                    }
                }
            }
            System.out.println(rowBuffer.toString());
            rowBuffer.setLength(0);
        }
    }
}

