package org.example;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.commons.codec.binary.Base64;


import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.security.KeyStore;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException {
        // Esample
        // good-user.p12
        // ks-password

        if(args.length != 2) {
            System.err.println("USAGE: org.example.Main fileToSign.txt certificate.p12");
            System.exit(1);
        }
        String fileName = args[0];
        String certificateName = args[1];

        Console cnsl = System.console();
        if (cnsl == null) {
            System.err.println(
                    "No console available");
            System.exit(1);
        }

        String certificatePass = cnsl.readLine("Certificate password : ");

        DSSDocument toSignDocument = new FileDocument(fileName);

        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(certificateName, new KeyStore.PasswordProtection(certificatePass.toCharArray()))) {

            /*List<DSSPrivateKeyEntry> keys = token.getKeys();
            for (DSSPrivateKeyEntry entry : keys) {
                System.out.println(entry.getCertificate().getCertificate());
            }*/

            XAdESService service = new XAdESService(new CommonCertificateVerifier());

            DSSPrivateKeyEntry privateKey = token.getKeys().get(0);

            // Preparing parameters for the XAdES signature
            XAdESSignatureParameters parameters = new XAdESSignatureParameters();
            // We choose the level of the signature (-B, -T, -LT, -LTA).
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            // We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            // We set the digest algorithm to use with the signature algorithm. You must use the
            // same parameter when you invoke the method sign on the token. The default value is SHA256
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());
            // We set the certificate chain

            parameters.setCertificateChain(privateKey.getCertificateChain());

            BLevelParameters bLevelParameters = new BLevelParameters();
            bLevelParameters.setSigningDate(new Date((long)1686056497658L));

            parameters.setBLevelParams(bLevelParameters);

            // Get the SignedInfo XML segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

            // We invoke the service to sign the document with the signature value obtained in
            // the previous step.
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
            //System.out.println(signedDocument);
            signedDocument.writeTo(baos);
            byte[] byteArray = baos.toByteArray();

            byte[] encodedBytes = Base64.encodeBase64(byteArray);
            System.out.println(new String(encodedBytes));

            // =====================================
            // The following is for the verification
            // =====================================


            /*
            SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

            // First, we need a Certificate verifier
            CertificateVerifier cv = new CommonCertificateVerifier();
            // We add    the certificate verifier (which allows to verify and trust certificates)
            documentValidator.setCertificateVerifier(cv);

            // Here, everything is ready. We can execute the validation (for the example, we use the default and embedded
            // validation policy)
            Reports reports = documentValidator.validateDocument();

            // We have 4 reports
            // The diagnostic data which contains all used and static data
            DiagnosticData diagnosticData = reports.getDiagnosticData();

            List<SignatureWrapper> signatures = diagnosticData.getSignatures();
            if (signatures != null) {
                Iterator var3 = signatures.iterator();

                while(var3.hasNext()) {
                    SignatureWrapper xmlSignature = (SignatureWrapper)var3.next();
                    System.out.println(xmlSignature.isSignatureValid());
                }
            }

            // The detailed report which is the result of the process of the diagnostic data and the validation policy
            DetailedReport detailedReport = reports.getDetailedReport();

            // The simple report is a summary of the detailed report (more user-friendly)
            SimpleReport simpleReport = reports.getSimpleReport();
             */
        }

    }
}