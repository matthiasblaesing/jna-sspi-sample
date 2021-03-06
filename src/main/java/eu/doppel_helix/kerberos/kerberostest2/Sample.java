package eu.doppel_helix.kerberos.kerberostest2;

import com.sun.jna.Memory;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.platform.win32.Sspi.PSecPkgInfo;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.ptr.IntByReference;
import static eu.doppel_helix.kerberos.kerberostest2.CommonUtil.ensureOk;
import static eu.doppel_helix.kerberos.kerberostest2.CommonUtil.printHexDump;
import eu.doppel_helix.kerberos.kerberostest2.SspiX.ManagedSecBufferDesc;
import eu.doppel_helix.kerberos.kerberostest2.SspiX.SEC_WINNT_AUTH_IDENTITY;
import eu.doppel_helix.kerberos.kerberostest2.SspiX.SecPkgContext_Lifespan;
import eu.doppel_helix.kerberos.kerberostest2.SspiX.SecPkgContext_NegotiationInfo;
import java.nio.charset.Charset;
import java.util.Base64;

public class Sample {

    public static void main(String[] args) {
        
        final String packageName = "Negotiate";
        
        PSecPkgInfo pkgInfo = new PSecPkgInfo();
        ensureOk(Secur32X.INSTANCE.QuerySecurityPackageInfo(packageName, pkgInfo));

        System.out.println("Security Package: " + packageName);
        System.out.println("Capabilities:\n" + String.join("\n", SECPKG_FLAG_Map.resolve(pkgInfo.pPkgInfo.fCapabilities)));
        
        final TimeStamp clientTimestamp = new TimeStamp();
        final TimeStamp serverTimestamp = new TimeStamp();
        final CredHandle serverCred = new CredHandle();
        final CredHandle clientCred = new CredHandle();
        
        // Secondary identity for test
        SEC_WINNT_AUTH_IDENTITY identity = new SspiX.SEC_WINNT_AUTH_IDENTITY();
        identity.User = "test";
        identity.Domain = "KONZERN.INTERN";
        identity.Password = "Satire1";
        identity.write();
        
        ensureOk(Secur32X.INSTANCE.AcquireCredentialsHandle(null, packageName, SspiX.SECPKG_CRED_INBOUND, null, null, null, null, serverCred, serverTimestamp));
        ensureOk(Secur32X.INSTANCE.AcquireCredentialsHandle(null, packageName, SspiX.SECPKG_CRED_OUTBOUND, null, identity.getPointer(), null, null, clientCred, clientTimestamp));
        
        SspiX.SecPkgCredentials_Names names = new SspiX.SecPkgCredentials_Names();
        ensureOk(Secur32X.INSTANCE.QueryCredentialsAttributes(serverCred, SspiX.SECPKG_CRED_ATTR_NAMES, names));
        
        String serverName = names.getUserName();
        
        names.free();
        
        names = new SspiX.SecPkgCredentials_Names();
        ensureOk(Secur32X.INSTANCE.QueryCredentialsAttributes(clientCred, SspiX.SECPKG_CRED_ATTR_NAMES, names));
        
        String clientName = names.getUserName();
        
        names.free();
        
        System.out.printf("Client name: %s%n", clientName);
        System.out.printf("Server name: %s%n", serverName);
        
        CtxtHandle clientCtx = new CtxtHandle();
        CtxtHandle serverCtx = new CtxtHandle();
        
        IntByReference serverContextAttr = new IntByReference();
        IntByReference clientContextAttr = new IntByReference();
        
        SspiX.ManagedSecBufferDesc serverToken = null;
        int clientRc = W32Errors.SEC_I_CONTINUE_NEEDED;
        int serverRc = W32Errors.SEC_I_CONTINUE_NEEDED;
        do {
            SspiX.ManagedSecBufferDesc pbClientToken = new SspiX.ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
            if (clientRc == W32Errors.SEC_I_CONTINUE_NEEDED) {
                SspiX.SecBufferDesc2 pbServerTokenCopy = serverToken == null
                        ? null : new SspiX.ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, serverToken.getBuffer(0).getBytes());
                clientRc = Secur32X.INSTANCE.InitializeSecurityContext(
                        clientCred,
                        clientCtx.isNull() ? null : clientCtx,
                        serverName,
                        Sspi.ISC_REQ_CONFIDENTIALITY | Sspi.ISC_REQ_DELEGATE,
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
                serverToken = new SspiX.ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
                SspiX.SecBufferDesc2 pbClientTokenByValue = new SspiX.ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, pbClientToken.getBuffer(0).getBytes());
                serverRc = Secur32X.INSTANCE.AcceptSecurityContext(
                        serverCred,
                        serverCtx.isNull() ? null : serverCtx,
                        pbClientTokenByValue,
                        0,
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

        System.out.print("\n");
        
        System.out.println("SRV - CONFIDENTIALITY: " + (serverContextAttr.getValue() & SspiX.ISC_REQ_CONFIDENTIALITY));
        System.out.println("CLT - CONFIDENTIALITY: " + (clientContextAttr.getValue() & SspiX.ISC_REQ_CONFIDENTIALITY));
        System.out.println("SRV - DELEGATION: " + (serverContextAttr.getValue() & SspiX.ISC_REQ_DELEGATE));
        System.out.println("CLT - DELEGATION: " + (clientContextAttr.getValue() & SspiX.ISC_REQ_DELEGATE));
        System.out.println("SRV - Mutual Auth: " + (serverContextAttr.getValue() & SspiX.ISC_REQ_MUTUAL_AUTH));
        System.out.println("CLT - Mutual Auth: " + (clientContextAttr.getValue() & SspiX.ISC_REQ_MUTUAL_AUTH));
        
        
        System.out.print("\n");
        
        SspiX.SecPkgContext_Sizes sizes = new SspiX.SecPkgContext_Sizes();
        ensureOk(Secur32X.INSTANCE.QueryContextAttributes(clientCtx, SspiX.SECPKG_ATTR_SIZES, sizes));
        
        System.out.println(sizes);
        
        System.out.print("\n");
        
        SecPkgContext_NegotiationInfo negotiateInfo = new SecPkgContext_NegotiationInfo();
        Secur32X.INSTANCE.QueryContextAttributes(clientCtx, SspiX.SECPKG_ATTR_NEGOTIATION_INFO, negotiateInfo);
        System.out.println("Negotiation State:  " + negotiateInfo.NegotiationState);
        System.out.println("Negotiated Package: " + negotiateInfo.PackageInfo.pPkgInfo.Name);
        negotiateInfo.free();
        
        System.out.print("\n");
        
        SecPkgContext_Lifespan lifespanInfo = new SecPkgContext_Lifespan();
        Secur32X.INSTANCE.QueryContextAttributes(clientCtx, SspiX.SECPKG_ATTR_LIFESPAN, lifespanInfo);
        System.out.println("LT-Start:  " + lifespanInfo.getStartAsDate());
        System.out.println("LT-Expiry: " + lifespanInfo.getExpiryAsDate());
        
        System.out.print("\n");
        
        SspiX.SecPkgContext_KeyInfo keyInfo = new SspiX.SecPkgContext_KeyInfo();
        
        Secur32X.INSTANCE.QueryContextAttributes(clientCtx, SspiX.SECPKG_ATTR_KEY_INFO, keyInfo);
        System.out.println("Encryption Algorithm:  " + keyInfo.getEncryptAlgorithmName());
        System.out.println("Signature Algorithm:   " + keyInfo.getSignatureAlgorithmName());
        System.out.println("Keysize:               " + keyInfo.KeySize);
        keyInfo.free();
        
        System.out.print("\n");
        
        SspiX.SecPkgContext_SessionKey sessionKey = new SspiX.SecPkgContext_SessionKey();
        
        Secur32X.INSTANCE.QueryContextAttributes(clientCtx, SspiX.SECPKG_ATTR_SESSION_KEY, sessionKey);
        System.out.println("Session Key length: " + sessionKey.SessionKeyLength);
        System.out.println("Session Key:        " + Base64.getEncoder().encodeToString(sessionKey.getSessionKey()));
        sessionKey.free();
        
        System.out.print("\n");
        
        byte[] inputData = "Hallo Welt".getBytes(Charset.forName("ASCII"));
        System.out.println("============ INPUT =============");
        printHexDump(inputData);
        
        
        System.out.println("\n============ EncryptMessage =============");
        
        ManagedSecBufferDesc encryptBuffers = new ManagedSecBufferDesc(2);
        
        Memory tokenMemory = new Memory(sizes.cbMaxToken);
        Memory dataMemory = new Memory(inputData.length);
        dataMemory.write(0, inputData, 0, inputData.length);
        
        encryptBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_TOKEN;
        encryptBuffers.getBuffer(0).cbBuffer = (int) tokenMemory.size();
        encryptBuffers.getBuffer(0).pvBuffer = tokenMemory;
        encryptBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
        encryptBuffers.getBuffer(1).cbBuffer = (int) dataMemory.size();
        encryptBuffers.getBuffer(1).pvBuffer = dataMemory;
        
        System.out.println("Struct-Size: " + encryptBuffers.size());
        
        ensureOk(Secur32X.INSTANCE.EncryptMessage(clientCtx, 0, encryptBuffers, 0));
        
        byte[] header = encryptBuffers.getBuffer(0).getBytes();
        byte[] messageResult = encryptBuffers.getBuffer(1).getBytes();
        printHexDump(header);
        printHexDump(messageResult);
        
        System.out.println("\n============ DecryptMessage =============");
        
        ManagedSecBufferDesc decryptBuffers = new ManagedSecBufferDesc(2);
        
        Memory decryptTokenMemory = new Memory(header.length);
        decryptTokenMemory.write(0, header, 0, header.length);
        Memory decryptDataMemory = new Memory(messageResult.length);
        decryptDataMemory.write(0, messageResult, 0, messageResult.length);
        
        decryptBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_TOKEN;
        decryptBuffers.getBuffer(0).cbBuffer = (int) decryptTokenMemory.size();
        decryptBuffers.getBuffer(0).pvBuffer = decryptTokenMemory;
        decryptBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
        decryptBuffers.getBuffer(1).cbBuffer = (int) decryptDataMemory.size();
        decryptBuffers.getBuffer(1).pvBuffer = decryptDataMemory;

        IntByReference qosResult = new IntByReference();
        ensureOk(Secur32X.INSTANCE.DecryptMessage(serverCtx, decryptBuffers, 0, qosResult));

        System.out.println("QOS: " + qosResult.getValue());
        byte[] decryptMessageResult = decryptBuffers.getBuffer(1).getBytes();
        printHexDump(decryptMessageResult);
        
        System.out.println("\n============ MakeSignature =============");
        
        ManagedSecBufferDesc signBuffers = new ManagedSecBufferDesc(2);
        
        Memory signTokenMemory = new Memory(sizes.cbMaxSignature);
        Memory signDataMemory = new Memory(inputData.length);
        signDataMemory.write(0, inputData, 0, inputData.length);
        
        signBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_TOKEN;
        signBuffers.getBuffer(0).cbBuffer = (int) signTokenMemory.size();
        signBuffers.getBuffer(0).pvBuffer = signTokenMemory;
        signBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
        signBuffers.getBuffer(1).cbBuffer = (int) signDataMemory.size();
        signBuffers.getBuffer(1).pvBuffer = signDataMemory;
        
        ensureOk(Secur32X.INSTANCE.MakeSignature(clientCtx, 0, signBuffers, 0));
        
        byte[] signToken = signBuffers.getBuffer(0).getBytes();
        byte[] signMessageResult = signBuffers.getBuffer(1).getBytes();
        printHexDump(signToken);
        printHexDump(signMessageResult);
        
        System.out.println("\n============ VerifySignature =============");
        
        ManagedSecBufferDesc verifyBuffers = new ManagedSecBufferDesc(2);
        
        Memory verifyTokenMemory = new Memory(signToken.length);
        verifyTokenMemory.write(0, signToken, 0, signToken.length);
        Memory verifyDataMemory = new Memory(signMessageResult.length);
        verifyDataMemory.write(0, signMessageResult, 0, signMessageResult.length);
        
        verifyBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_TOKEN;
        verifyBuffers.getBuffer(0).cbBuffer = (int) verifyTokenMemory.size();
        verifyBuffers.getBuffer(0).pvBuffer = verifyTokenMemory;
        verifyBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
        verifyBuffers.getBuffer(1).cbBuffer = (int) verifyDataMemory.size();
        verifyBuffers.getBuffer(1).pvBuffer = verifyDataMemory;

        IntByReference qosSigingResult = new IntByReference();
        ensureOk(Secur32X.INSTANCE.VerifySignature(serverCtx, verifyBuffers, 0, qosSigingResult));

        System.out.println("QOS: " + qosSigingResult.getValue());
        printHexDump(signMessageResult);
        
        ensureOk(Secur32X.INSTANCE.ImpersonateSecurityContext(serverCtx));
        System.out.println(Advapi32Util.getUserName());
        ensureOk(Secur32X.INSTANCE.RevertSecurityContext(serverCtx));
        
        ensureOk(Secur32X.INSTANCE.DeleteSecurityContext(clientCtx));
        ensureOk(Secur32X.INSTANCE.DeleteSecurityContext(serverCtx));
        
        ensureOk(Secur32X.INSTANCE.FreeCredentialsHandle(clientCred));
        ensureOk(Secur32X.INSTANCE.FreeCredentialsHandle(serverCred));
    }
}

