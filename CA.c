// Here i am using client's chat portal username as common name for the x509 certificate. 

#include "header/CA.h"
#include "header/common_header.h"

/*********** CA Certificate .pem file. ****************************/
#define CACERT "CA_Cert/cacert.pem"
/*********** CA's Private Key file. *******************************/
#define CAKEY "CA_Cert/cakey.pem"

#define DATE_LEN 128

BIO * outbio = NULL;

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len) {
	int rc;
	BIO * b = BIO_new(BIO_s_mem());
	
	rc = ASN1_TIME_print(b, t);
	if (rc <= 0) {
		BIO_free(b);
		return -1;
	}
	
	rc = BIO_gets(b, buf, len);
	if (rc <= 0) {
		BIO_free(b);
		return -1;
	}

	BIO_free(b);
	return 1;
}

/* Generates a 2048-bit RSA key. */
EVP_PKEY * generate_key() {
    /* Allocate memory for the EVP_PKEY structure. */
	EVP_PKEY * pkey = EVP_PKEY_new();
	
	if(!pkey) {
		BIO_printf(outbio, "Unable to create EVP_PKEY structure.\n");
		return NULL;
	}

    /* Generate the RSA key and assign it to pkey. */
	RSA * rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	
	if(!EVP_PKEY_assign_RSA(pkey, rsa)) {
		BIO_printf(outbio, "Unable to generate 2048-bit RSA key.\n");
		EVP_PKEY_free(pkey);
		return NULL;
	}

    /* The key has been generated, return it. */
	return pkey;
}

/* Generates a X.509 certificate signed by CA. */
X509 * generate_x509(EVP_PKEY * pkey, char * common_name,
						char * country_code, char * organization_name) {
	/* C file descriptor */
	FILE * fp;
	/* Allocate memory for the X509 structure for CA. */
	X509 * cacert;
	
	/* -------------------------------------------------------- *
	 * Load the signing CA Certificate file.                    *
	 * ---------------------------------------------------------*/
	if (! (fp=fopen(CACERT, "r"))) {
		BIO_printf(outbio, "Error reading CA cert file.\n");
		return NULL;
	}

	if(! (cacert = PEM_read_X509(fp,NULL,NULL,NULL))) {
		BIO_printf(outbio, "Error loading CA cert into memory.\n");
		return NULL;
	}

	fclose(fp);

	/* -------------------------------------------------------- *
	 * Import CA Private Key file for signing.                  *
	 * ---------------------------------------------------------*/
	EVP_PKEY * ca_privkey = EVP_PKEY_new();

	if (! (fp = fopen (CAKEY, "r"))) {
		BIO_printf(outbio, "Error reading CA private key file.\n");
		return NULL;
	}

	if (! (ca_privkey = PEM_read_PrivateKey( fp, NULL, NULL, NULL))) {
		BIO_printf(outbio, "Error importing key content from file.\n");
		return NULL;
	}

	fclose(fp);

	/* Allocate memory for the X509 structure for certificate requesting party. */
	X509 * x509 = X509_new();
	
	if(!x509) {
		BIO_printf(outbio, "Unable to create X509 structure.\n");
		return NULL;
	}

    /* Set the serial number. */
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now. */
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

	/* Generate a public key for certificate requesting party. */
	EVP_PKEY * pubkey = generate_key();

    /* Set the public key for our certificate. */
	X509_set_pubkey(x509, pkey);

    /* Certificate issuer name. */
	X509_NAME * issuer_name;
	X509_NAME * subject_name = X509_get_subject_name(x509);

	/* Extract the subject name from the signing CA Certificate. */
	if (! (issuer_name = X509_get_subject_name(cacert))) {
		BIO_printf(outbio, "Error getting subject from CA certificate.\n");
		return NULL;
	}

	/* Now set the issuer name. */
	X509_set_issuer_name(x509, issuer_name);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC,
									(unsigned char *)common_name, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject_name, "C",  MBSTRING_ASC,
									(unsigned char *)country_code, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject_name, "O",  MBSTRING_ASC,
									(unsigned char *)organization_name, -1, -1, 0);

    /* Sign the certificate with CA's private key. */
	if(!X509_sign(x509, ca_privkey, EVP_sha256())) {
		BIO_printf(outbio, "Error signing certificate.\n");
		X509_free(x509);
		return NULL;
	}

	return x509;
}

int write_to_disk(EVP_PKEY * pkey, X509 * x509, char * common_name) {
	char cert_path[50] = "Client_Cert/cert/";
	char key_path[50] = "Client_Cert/key/";

	strcat(cert_path, common_name);
	strcat(cert_path, ".pem");
	strcat(key_path, common_name);
	strcat(key_path, ".pem");

    /* Open the PEM file for writing the key to disk. */
	FILE * pkey_file = fopen(key_path, "wb");
	
	if(!pkey_file) {
		BIO_printf(outbio, "Unable to open key file for writing.\n");
		return -1;
	}

    /* Write the key to disk. */
	int ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(pkey_file);

	if(!ret) {
		BIO_printf(outbio, "Unable to write private key to disk.\n");
		return -1;
	}

    /* Open the PEM file for writing the certificate to disk. */
	FILE * x509_file = fopen(cert_path, "wb");
	
	if(!x509_file) {
		BIO_printf(outbio, "Unable to open certificate file for writing.\n");
		return -1;
	}

    /* Write the certificate to disk. */
	ret = PEM_write_X509(x509_file, x509);
	fclose(x509_file);

	if(!ret) {
		BIO_printf(outbio, "Unable to write certificate to disk.\n");
		return -1;
	}

	return 1;
}

int cert_exists(char * common_name, char * country_code, char * organization_name) {
	char cert_path[50] = "Client_Cert/cert/";
	FILE * cert_file;
	X509 * cert;

	strcat(cert_path, common_name);
	strcat(cert_path, ".pem");

	/* Check if the certificate already exists. */
	if( access(cert_path, F_OK ) != -1 ) {
		/* Certificate exists. */

    	/* -------------------------------------------------------- *
		 * Load the Certificate file.                               *
		 * ---------------------------------------------------------*/
		if ((cert_file=fopen(cert_path, "r")) && 
					(cert = PEM_read_X509(cert_file, NULL, NULL, NULL))) {
			/* Extracting subject fields from certificate. */
			X509_NAME * subj = X509_get_subject_name(cert);

			/* Extracting Username from certificate. */
			X509_NAME_ENTRY * e1 = X509_NAME_get_entry(subj, 0);
			ASN1_STRING * a1 = X509_NAME_ENTRY_get_data(e1);
			char * cert_common_name = ASN1_STRING_data(a1);

			/* Extracting Country Code from certificate. */
			X509_NAME_ENTRY * e2 = X509_NAME_get_entry(subj, 1);
			ASN1_STRING * a2 = X509_NAME_ENTRY_get_data(e2);
			char * cert_country_code = ASN1_STRING_data(a2);

			/* Extracting Organization Name from certificate. */
			X509_NAME_ENTRY * e3 = X509_NAME_get_entry(subj, 2);
			ASN1_STRING * a3 = X509_NAME_ENTRY_get_data(e3);
			char * cert_organization_name = ASN1_STRING_data(a3);

			fprintf(stdout, "\nUsername in already present certificate: %s\n",
					cert_common_name);
			fprintf(stdout, "Country Code in already present certificate: %s\n",
					cert_country_code);
			fprintf(stdout, "Organization name in already present certificate: %s\n\n",
					cert_organization_name );


			/* Check if all the request fields match with existing fields in the certificate. */
			if (strcmp(common_name, cert_common_name) == 0) {
				if (strcmp(country_code, cert_country_code) == 0 &&
					strcmp(organization_name, cert_organization_name) == 0) {
					/* Match occurs. */
					/* Check if certificate is valid or not. */
					ASN1_TIME * not_before = X509_get_notBefore(cert);
					ASN1_TIME * not_after = X509_get_notAfter(cert);

					char not_before_str[DATE_LEN];
					if (convert_ASN1TIME(not_before, not_before_str, DATE_LEN) == 1) {
						fprintf(stdout, "Existing certificate not valid before: %s\n", not_before_str);
					}

					char not_after_str[DATE_LEN];
					if (convert_ASN1TIME(not_after, not_after_str, DATE_LEN) == 1) {
						fprintf(stdout, "Existing certificate not valid after: %s\n", not_after_str);
					}

					int day, sec;

					if (ASN1_TIME_diff(&day, &sec, NULL, not_after) != 0) {
						if (day > 0 || sec > 0) {
							printf("\nExisting certificate is valid.\n");
							return 1;
						}
						else if (day < 0 || sec < 0) {
							printf("\nExisting certificate is not valid. Issuing new certificate.\n");
							return -1;
						}
						else {
							printf("\nExisting certificate is valid.\n");
							return 1;
						}
					}
				}
				else {
					fprintf(stdout, "Certificate with the same Username already exists.");
					fprintf(stdout, " Try sending CSR with a valid Username.\n");
					return 0;
				}
			}

			return -1;
		}
		/* Certificate exists but is corrupted.	*/
		else {
			return -1;
		}

		fclose(cert_file);
	}

	/* Certificate doesn't exists. */
	return -1;
}

/* Certificate Signing Request. */
int csr(char * common_name, char * country_code, char * organization_name) {
	/* ---------------------------------------------------------- *
	 * These function calls initialize openssl for correct work.  *
	 * ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	
	/* ---------------------------------------------------------- *
	 * Create the Input/Output BIO's.                             *
	 * ---------------------------------------------------------- */
	outbio  = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* First check whether the certificate already exists and is valid. */
	int ret = cert_exists(common_name, country_code, organization_name);
	if (ret == 1) {
		return 0;
	}
	else if (ret == 0) {
		/* If there exists a certificate with same Username. */
		return -1;
	}

    /* Generate the key. */
	BIO_printf(outbio, "\nGenerating RSA key...\n");

	EVP_PKEY * pkey = generate_key();
	
	if(!pkey) {
		return -1;
	}

    /* Generate the certificate. */
	BIO_printf(outbio, "Generating x509 certificate...\n");

	X509 * x509 = generate_x509(pkey, common_name, country_code, organization_name);
	
	if(!x509) {
		EVP_PKEY_free(pkey);
		return -1;
	}

	ret = write_to_disk(pkey, x509, common_name);
	EVP_PKEY_free(pkey);
	X509_free(x509);

	if(ret == 1) {
		BIO_printf(outbio, "Success!\n");
		return 1;
	}
	else {
		return -1;
	}
}