import assert from "assert";
import nsblob from "nsblob64";
import * as openpgp from "openpgp";

const GENERIC_DESER_ERROR =
	"Token.fromHash() was passed something that is not a Token";

export class Token<T> {
	protected _data: T;
	protected _signed = false;
	protected _signatures = new Array<string>();

	constructor(data: T) {
		this._data = data;
	}

	get data(): T {
		return typeof this._data === "object"
			? Object.setPrototypeOf({}, this._data)
			: this._data;
	}

	async datahash(): Promise<string> {
		return await nsblob.store_json(this._data);
	}

	async hash(): Promise<string> {
		return await nsblob.store_json({
			data: await this.datahash(),
			signatures: this._signatures,
		});
	}

	async sign(key: openpgp.PrivateKey) {
		const datahash = await this.datahash();

		const signature = await openpgp.sign({
			message: await openpgp.createMessage({ text: datahash }),
			signingKeys: [key],
		});

		this._signatures.push(await nsblob.store(signature));

		return await this.hash();
	}

	async verify(key: openpgp.PublicKey) {
		for (const signature of this._signatures) {
			try {
				const armoredMessage = String(await nsblob.fetch(signature));
				const message = await openpgp.readMessage({ armoredMessage });

				const { data } = await openpgp.verify({
					message,
					verificationKeys: [key],
					expectSigned: true,
				});

				assert(
					data === (await this.datahash()),
					"Data does not match signature!"
				);

				return true;
			} catch (error) {
				console.error(error);

				return false;
			}
		}

		return false;
	}

	static async fromHash(hash: string, key: openpgp.PublicKey) {
		const fetched = await nsblob.fetch_json(hash);

		assert(typeof fetched === "object", GENERIC_DESER_ERROR);
		assert(fetched, GENERIC_DESER_ERROR);
		assert("data" in fetched, GENERIC_DESER_ERROR);
		assert(typeof fetched.data === "string", GENERIC_DESER_ERROR);
		assert("signatures" in fetched, GENERIC_DESER_ERROR);
		assert(Array.isArray(fetched.signatures), GENERIC_DESER_ERROR);

		for (const signature of fetched.signatures) {
			assert(typeof signature === "string", GENERIC_DESER_ERROR);
			assert(signature.length === 43, GENERIC_DESER_ERROR);
		}

		const { data, signatures } = fetched;

		const token = new Token(await nsblob.fetch_json(data));

		token._signatures = signatures;

		assert(await token.verify(key), "Token verification failed.");

		return token;
	}
}
