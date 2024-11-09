#pragma once
#include <string>
#include <fstream>
#include <utility>
#include <filesystem>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


namespace fs = std::filesystem;

namespace EAD {

	typedef std::pair<bool,std::string> ER;

	std::string base64Encode(const std::string& binaryData) {
		BIO *bio, *b64;
		BUF_MEM *bufferPtr;

		b64 = BIO_new(BIO_f_base64());
		bio = BIO_new(BIO_s_mem());
		bio = BIO_push(b64, bio);

		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // 改行なしオプション
		BIO_write(bio, binaryData.data(), binaryData.size());
		BIO_flush(bio);
		BIO_get_mem_ptr(bio, &bufferPtr);

		std::string base64Text(bufferPtr->data, bufferPtr->length);
		BIO_free_all(bio);

		return base64Text;
	}
	std::string base64Decode(const std::string& base64Text) {
		BIO* bio, * b64;
		char* buffer = (char*)malloc(base64Text.size());
		memset(buffer, 0, base64Text.size());

		bio = BIO_new_mem_buf(base64Text.data(), base64Text.size());
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_push(b64, bio);
		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // 改行なしオプション

		int decodedSize = BIO_read(bio, buffer, base64Text.size());
		std::string binaryData(buffer, decodedSize);

		BIO_free_all(bio);
		free(buffer);

		return binaryData;
	}

	ER generateKeys(std::string folder, int bits = 2048) {
		// 公開指数をBIGNUMとして設定
		BIGNUM* e = BN_new();
		if (!BN_set_word(e, RSA_F4)) {
			BN_free(e);
			return {false, "Failed to create BIGNUM for public exponent"};
		}

		// 新しいRSAオブジェクトを生成
		RSA* rsa = RSA_new();
		if (!RSA_generate_key_ex(rsa, bits, e, nullptr)) {
			RSA_free(rsa);
			BN_free(e);
			return {false, "RSA key generation failed"};
		}

		// 公開鍵をファイルに保存
		FILE* pubFile = fopen((folder + "public.pem").c_str(), "wb");
		if (pubFile) {
			PEM_write_RSA_PUBKEY(pubFile, rsa);
			fclose(pubFile);
		} else {
			RSA_free(rsa);
			BN_free(e);
			return {false, "Unable to open public_key.pem for writing"};
		}

		// 秘密鍵をファイルに保存
		FILE* privFile = fopen((folder + "private.pem").c_str(), "wb");
		if (privFile) {
			PEM_write_RSAPrivateKey(privFile, rsa, nullptr, nullptr, 0, nullptr, nullptr);
			fclose(privFile);
		} else {
			RSA_free(rsa);
			BN_free(e);
			return {false, "Unable to open private_key.pem for writing"};
		}

		// リソースを解放
		RSA_free(rsa);
		BN_free(e);
		return {true, ""};
	}
	
	ER encryptText(const std::string& data, const std::string& pubKeyFile) {
		FILE* pubFile = fopen(pubKeyFile.c_str(), "rb");
		if (!pubFile) {
			return {false, "Unable to open public key file"};
		}
			
		RSA* rsa = PEM_read_RSA_PUBKEY(pubFile, nullptr, nullptr, nullptr);
		fclose(pubFile);

		if (!rsa) {
			return {false, "Unable to load public key"};
		}

		int rsaLen = RSA_size(rsa);
		std::string encrypted(rsaLen, '\0');
			
		int result = RSA_public_encrypt(data.size(), reinterpret_cast<const unsigned char*>(data.c_str()),
										reinterpret_cast<unsigned char*>(&encrypted[0]), rsa, RSA_PKCS1_PADDING);
			
		RSA_free(rsa);

		if (result == -1) {
			return {false, "Encryption failed"};
		}

		// 暗号化されたバイナリデータをBase64エンコードして返す
		return {true, base64Encode(encrypted)};
	}

	ER decryptText(const std::string& encryptedTextBase64, const std::string& privKeyFile) {
		// Base64テキストをデコードしてバイナリ形式に戻す
		std::string encryptedText = base64Decode(encryptedTextBase64);

		FILE* privFile = fopen(privKeyFile.c_str(), "rb");
		if (!privFile) {
			return {false, "Unable to open private key file"};
		}

		RSA* rsa = PEM_read_RSAPrivateKey(privFile, nullptr, nullptr, nullptr);
		fclose(privFile);

		if (!rsa) {
			return {false, "Unable to load private key"};
		}

		int rsaLen = RSA_size(rsa);
		std::string decrypted(rsaLen, '\0');

		int result = RSA_private_decrypt(encryptedText.size(),
										 reinterpret_cast<const unsigned char*>(encryptedText.c_str()),
										 reinterpret_cast<unsigned char*>(&decrypted[0]),
										 rsa, RSA_PKCS1_PADDING);

		RSA_free(rsa);

		if (result == -1) {
			return {false, "Decryption failed"};
		}

		decrypted.resize(result);  // 正確なデータ長に調整
		return {true, decrypted};
	}

	// AESキーとIVを生成
	std::pair<std::string, std::string> generateAESKeyAndIV() {
		std::string key(32, '\0'); // AES-256の鍵は32バイト
		std::string iv(16, '\0');  // AESのIVは16バイト

		RAND_bytes(reinterpret_cast<unsigned char*>(&key[0]), key.size());
		RAND_bytes(reinterpret_cast<unsigned char*>(&iv[0]), iv.size());

		return { key, iv };
	}

	// AESによるデータの暗号化
	std::string aesEncrypt(const std::string& data, const std::string& key, const std::string& iv) {
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()),
						   reinterpret_cast<const unsigned char*>(iv.c_str()));

		std::string ciphertext(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()), '\0');
		int len = 0, ciphertext_len = 0;

		EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
						  reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
		ciphertext_len += len;

		EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + ciphertext_len, &len);
		ciphertext_len += len;
		ciphertext.resize(ciphertext_len);

		EVP_CIPHER_CTX_free(ctx);
		return ciphertext;
	}

	// AESによるデータの復号
	std::string aesDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()),
						   reinterpret_cast<const unsigned char*>(iv.c_str()));

		std::string plaintext(ciphertext.size(), '\0');
		int len = 0, plaintext_len = 0;

		EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
						  reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
		plaintext_len += len;

		EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + plaintext_len, &len);
		plaintext_len += len;
		plaintext.resize(plaintext_len);

		EVP_CIPHER_CTX_free(ctx);
		return plaintext;
	}

	// RSAでAESキーを暗号化
	std::string rsaEncryptKey(const std::string& aesKey, const std::string& pubKeyFile) {
		FILE* pubFile = fopen(pubKeyFile.c_str(), "rb");
		if (!pubFile) {
			return "";
		}

		RSA* rsa = PEM_read_RSA_PUBKEY(pubFile, nullptr, nullptr, nullptr);
		fclose(pubFile);
		if (!rsa) {
			return "";
		}

		std::string encryptedKey(RSA_size(rsa), '\0');
		int len = RSA_public_encrypt(aesKey.size(), reinterpret_cast<const unsigned char*>(aesKey.c_str()),
									 reinterpret_cast<unsigned char*>(&encryptedKey[0]), rsa, RSA_PKCS1_PADDING);
		RSA_free(rsa);

		if (len == -1) return "";
		encryptedKey.resize(len);
		return base64Encode(encryptedKey);
	}

	// RSAでAESキーを復号
	std::string rsaDecryptKey(const std::string& encryptedKeyBase64, const std::string& privKeyFile) {
		std::string encryptedKey = base64Decode(encryptedKeyBase64);

		FILE* privFile = fopen(privKeyFile.c_str(), "rb");
		if (!privFile) return "";

		RSA* rsa = PEM_read_RSAPrivateKey(privFile, nullptr, nullptr, nullptr);
		fclose(privFile);
		if (!rsa) return "";

		std::string decryptedKey(RSA_size(rsa), '\0');
		int len = RSA_private_decrypt(encryptedKey.size(), reinterpret_cast<const unsigned char*>(encryptedKey.c_str()),
									  reinterpret_cast<unsigned char*>(&decryptedKey[0]), rsa, RSA_PKCS1_PADDING);
		RSA_free(rsa);

		if (len == -1) return "";
		decryptedKey.resize(len);
		return decryptedKey;
	}

	// ハイブリッド暗号方式によるファイルの暗号化
	ER encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& pubKeyFile) {
		std::ifstream inputFile(inputFilePath, std::ios::binary);
		if (!inputFile) return { false, "Unable to open input file" };
		
		std::string fileData((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
		inputFile.close();

		auto [aesKey, iv] = generateAESKeyAndIV();
		std::string encryptedData = aesEncrypt(fileData, aesKey, iv);
		std::string encryptedKey = rsaEncryptKey(aesKey, pubKeyFile);

		if (encryptedKey.empty()) return { false, "RSA encryption of AES key failed" };

		std::ofstream outputFile(outputFilePath, std::ios::binary);
		if (!outputFile) return { false, "Unable to open output file" };

		outputFile << encryptedKey << "\n" << base64Encode(iv) << "\n" << base64Encode(encryptedData);
		outputFile.close();

		return { true, "File encrypted successfully" };
	}

	// ハイブリッド暗号方式によるファイルの復号
	ER decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& privKeyFile) {
		std::ifstream inputFile(inputFilePath, std::ios::binary);
		if (!inputFile) return { false, "Unable to open input file" };

		std::string encryptedKey, ivBase64, encryptedDataBase64;
		std::getline(inputFile, encryptedKey);
		std::getline(inputFile, ivBase64);
		std::getline(inputFile, encryptedDataBase64);
		inputFile.close();

		std::string aesKey = rsaDecryptKey(encryptedKey, privKeyFile);
		if (aesKey.empty()) return { false, "RSA decryption of AES key failed" };

		std::string iv = base64Decode(ivBase64);
		std::string encryptedData = base64Decode(encryptedDataBase64);
		std::string decryptedData = aesDecrypt(encryptedData, aesKey, iv);

		std::ofstream outputFile(outputFilePath, std::ios::binary);
		if (!outputFile) return { false, "Unable to open output file" };

		outputFile.write(decryptedData.data(), decryptedData.size());
		outputFile.close();

		return { true, "File decrypted successfully" };
	}
}