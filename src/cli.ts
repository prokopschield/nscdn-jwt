#!/usr/bin/env node

import nsblob from "nsblob64";

import { createToken, readToken, usePrivateKeyFile } from ".";

async function main() {
	const privateKey = await usePrivateKeyFile();

	for (const arg of process.argv.slice(2)) {
		if (arg.length === 43) {
			console.log(await readToken(arg, privateKey));
		} else {
			console.log(await createToken(arg, privateKey));
		}
	}

	nsblob.socket.close();
}

main();
