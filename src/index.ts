import fs from "fs";
import * as openpgp from "openpgp";
import os from "os";
import path from "path";

import { Token } from "./token";

export { openpgp, Token };

/**
 * Create a token from some data
 * @param data data to be embedded in token (must be JSON-encodable)
 * @param key private key to sign the token
 * @returns the token as a base64 string
 */
export async function createToken<T>(
	data: T,
	key: openpgp.PrivateKey
): Promise<string> {
	const token = new Token<T>(data);

	await token.sign(key);

	return await token.hash();
}

/**
 * Read a token, return its contents
 * @param token the token to read (may be user input)
 * @param key private key used to create the token
 * @returns the data in the token, or false if token is invalid
 */
export async function readToken(token: string, key: openpgp.PrivateKey) {
	try {
		const token_object = await Token.fromHash(token, key.toPublic());

		token_object.verify(key.toPublic());

		return token_object.data;
	} catch {
		return false;
	}
}

export async function loadPrivateKeyFile(
	file: string
): Promise<openpgp.PrivateKey> {
	const key_data = await fs.promises.readFile(file, "utf-8");

	return await openpgp.readPrivateKey({ armoredKey: key_data });
}

export async function createPrivateKeyFile(
	file: string
): Promise<openpgp.PrivateKey> {
	const directory = path.resolve(file, "..");

	if (!fs.existsSync(directory)) {
		await fs.promises.mkdir(directory, { recursive: true });
	}

	const { privateKey } = await openpgp.generateKey({
		userIDs: [{ name: process.env.NAME || process.env.USER }],
		curve: "ed25519",
		format: "object",
	});

	await fs.promises.writeFile(file, privateKey.armor());
	await fs.promises.chmod(file, 0o400);

	return privateKey;
}

export async function usePrivateKeyFile(
	file: string = path.resolve(os.homedir(), ".config/nscdn-jwt/private.key")
): Promise<openpgp.PrivateKey> {
	try {
		return await loadPrivateKeyFile(file);
	} catch {
		return await createPrivateKeyFile(file);
	}
}
